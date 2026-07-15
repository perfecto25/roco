require "socket"
require "./socket_utils"
require "./config"
require "./logger"

class TCPProxy
  HANDSHAKE_PREFIX = "ROCO2 "
  HANDSHAKE_MAX    = 4096
  BUFFER_SIZE      = 4096

  # End-to-end connection status, sent back up the chain once the far end has
  # been reached (or failed). Lets the originator tear down the client instead
  # of leaving it half-open when a downstream hop cannot reach the target.
  STATUS_OK  = "ROCO-OK"
  STATUS_ERR = "ROCO-ERR"

  def initialize(@config : Config)
  end

  def handle_client(client : TCPSocket) : Void
    server = nil.as(TCPSocket?)
    begin
      resolved = determine_chain(client)
      unless resolved
        Logger.warn("proxy", "Could not determine destination — dropping connection")
        return
      end
      chain, client_is_peer = resolved
      if chain.empty?
        Logger.warn("proxy", "Empty route — dropping connection")
        return
      end

      next_hop = chain.first
      remaining = chain[1..]

      # Connect to the next hop. On failure, report it back upstream (if the
      # client is a roco peer) so the originator can surface it, then bail.
      begin
        addr = next_hop.resolve_address
        if remaining.empty?
          Logger.info("proxy", "Forwarding to #{next_hop.host}:#{next_hop.port} (final hop)")
        else
          Logger.info("proxy", "Forwarding to #{next_hop.host}:#{next_hop.port}, then #{remaining.map(&.to_handshake).join(" -> ")}")
        end
        server = TCPSocket.new(addr, next_hop.port)
        Logger.info("proxy", "Connected to #{next_hop.host}:#{next_hop.port} (#{addr})")
      rescue e
        Logger.error("proxy", "Error connecting to '#{next_hop.host}:#{next_hop.port}': #{e.message}")
        send_status(client, false, e.message) if client_is_peer
        return
      end

      # Determine the end-to-end status. A terminal hop just connected to the
      # real target, so success is implied; an intermediate hop must wait for
      # the status propagated back from deeper in the chain.
      if remaining.empty?
        status_ok, status_msg = true, nil.as(String?)
      else
        write_handshake(server, remaining)
        status_ok, status_msg = read_status(server)
      end

      # Relay the verdict upstream when our client is another roco node.
      send_status(client, status_ok, status_msg) if client_is_peer

      unless status_ok
        Logger.warn("proxy", "Route down: #{status_msg} — closing connection")
        return
      end

      proxy_bidirectional(client, server)
    rescue e
      Logger.error("proxy", "#{e.message}")
    ensure
      client.close rescue nil
      server.try &.close rescue nil
    end
  end

  # Returns the resolved chain plus whether the client is a roco peer (arrived
  # via handshake) rather than a locally-redirected application.
  private def determine_chain(client : TCPSocket) : Tuple(Array(Hop), Bool)?
    # Locally REDIRECTed: kernel knows the original destination.
    ip, port = SocketUtils.get_original_destination(client)
    if ip && port
      Logger.info("proxy", "Locally redirected, original destination #{ip}:#{port}")
      return {build_chain_from_config(ip, port), false}
    end

    # Peer roco connection: read handshake.
    hops = read_handshake(client)
    if hops
      Logger.info("proxy", "Peer handshake, route #{hops.map(&.to_handshake).join(" -> ")}")
      return {hops, true}
    end

    Logger.warn("proxy", "No original destination and no valid handshake")
    nil
  end

  private def send_status(sock : TCPSocket, ok : Bool, msg : String?) : Void
    line = ok ? "#{STATUS_OK}\n" : "#{STATUS_ERR} #{msg}\n"
    sock.print line
    sock.flush
  rescue
  end

  private def read_status(sock : TCPSocket) : Tuple(Bool, String?)
    sock.read_timeout = 10.seconds
    begin
      line = String.build do |io|
        HANDSHAKE_MAX.times do
          b = sock.read_byte
          break if b.nil? || b == '\n'.ord
          io.write_byte(b.to_u8)
        end
      end

      if line.starts_with?(STATUS_OK)
        {true, nil}
      elsif line.starts_with?(STATUS_ERR)
        {false, line[STATUS_ERR.size..].strip}
      else
        {false, "invalid status from downstream"}
      end
    ensure
      sock.read_timeout = nil
    end
  rescue
    {false, "no status from downstream (timeout)"}
  end

  private def build_chain_from_config(dest_ip : String, dest_port : UInt16) : Array(Hop)
    route = @config.find_route(dest_ip)
    if route
      relay, matched_target = route
      host = (relay.resolve_dns && hostname_like?(matched_target)) ? matched_target : dest_ip
      relay.chain + [Hop.new(host, dest_port)]
    else
      [Hop.new(dest_ip, dest_port)]
    end
  end

  private def hostname_like?(s : String) : Bool
    !s.includes?("/") && !/\A(\d{1,3}\.){3}\d{1,3}\z/.matches?(s)
  end

  private def read_handshake(client : TCPSocket) : Array(Hop)?
    client.read_timeout = 5.seconds
    begin
      line = String.build do |io|
        HANDSHAKE_MAX.times do
          b = client.read_byte
          break if b.nil? || b == '\n'.ord
          io.write_byte(b.to_u8)
        end
      end

      return nil unless line.starts_with?(HANDSHAKE_PREFIX)
      payload = line[HANDSHAKE_PREFIX.size..]
      hops = payload.split(' ').reject(&.empty?).map do |s|
        Hop.parse(s, @config.port)
      end
      return nil if hops.empty?
      hops
    ensure
      client.read_timeout = nil
    end
  rescue
    nil
  end

  private def write_handshake(server : TCPSocket, hops : Array(Hop)) : Void
    line = String.build do |io|
      io << HANDSHAKE_PREFIX
      hops.each_with_index do |h, i|
        io << " " if i > 0
        io << h.to_handshake
      end
      io << "\n"
    end
    server.print line
    server.flush
  end

  private def proxy_bidirectional(client : TCPSocket, server : TCPSocket) : Void
    channel = Channel(Nil).new

    spawn do
      copy_stream(client, server)
      channel.send(nil)
    end

    spawn do
      copy_stream(server, client)
      channel.send(nil)
    end

    # As soon as one direction ends, close both sockets so the other fiber
    # unblocks instead of leaving the connection half-open.
    channel.receive
    client.close rescue nil
    server.close rescue nil
    channel.receive
  end

  private def copy_stream(from : TCPSocket, to : TCPSocket) : Void
    buffer = Bytes.new(BUFFER_SIZE)
    loop do
      bytes_read = from.read(buffer)
      break if bytes_read == 0
      to.write(buffer[0, bytes_read])
      to.flush
    end
  rescue
  end
end

class RelayServer
  def initialize(@config : Config)
    @server = TCPServer.new("0.0.0.0", @config.port)
  end

  def start : Void
    Logger.info("relay", "Listening on 0.0.0.0:#{@config.port}")

    loop do
      begin
        client = @server.accept
        peer = (client.remote_address.to_s rescue "unknown")
        Logger.info("relay", "Connection from #{peer}")
        spawn do
          TCPProxy.new(@config).handle_client(client)
        end
      rescue e : Socket::Error
        break
      end
    end
  end

  def close : Void
    @server.close
  end
end
