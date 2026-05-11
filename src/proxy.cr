require "socket"
require "./socket_utils"
require "./config"

class TCPProxy
  HANDSHAKE_PREFIX = "ROCO1 "
  HANDSHAKE_MAX    = 256
  BUFFER_SIZE      = 4096

  def initialize(@config : Config)
  end

  def handle_client(client : TCPSocket) : Void
    server = nil.as(TCPSocket?)
    begin
      dest_ip, dest_port = determine_destination(client)

      unless dest_ip && dest_port
        puts "[proxy] Could not determine destination — dropping connection"
        return
      end

      next_hop = @config.find_next_hop(dest_ip)
      if next_hop
        relay_addr = next_hop.resolve_address
        relay_port = next_hop.port
        puts "[proxy] #{dest_ip}:#{dest_port} via relay '#{next_hop.name}' (#{relay_addr}:#{relay_port})"
        server = TCPSocket.new(relay_addr, relay_port)
        write_handshake(server, dest_ip, dest_port)
      else
        puts "[proxy] Direct to #{dest_ip}:#{dest_port}"
        server = TCPSocket.new(dest_ip, dest_port)
      end

      proxy_bidirectional(client, server)
    rescue e
      puts "[proxy] Error: #{e.message}"
    ensure
      client.close rescue nil
      server.try &.close rescue nil
    end
  end

  private def determine_destination(client : TCPSocket) : {String?, UInt16?}
    # Locally REDIRECTed connection — kernel knows the original dest.
    ip, port = SocketUtils.get_original_destination(client)
    return {ip, port} if ip && port

    # Otherwise the peer is a roco node that prefixed a handshake.
    read_handshake(client)
  end

  private def read_handshake(client : TCPSocket) : {String?, UInt16?}
    client.read_timeout = 5.seconds
    begin
      line = String.build do |io|
        HANDSHAKE_MAX.times do
          b = client.read_byte
          break if b.nil? || b == '\n'.ord
          io.write_byte(b.to_u8)
        end
      end

      return {nil, nil} unless line.starts_with?(HANDSHAKE_PREFIX)
      parts = line[HANDSHAKE_PREFIX.size..].split(' ')
      return {nil, nil} unless parts.size == 2
      {parts[0], parts[1].to_u16}
    ensure
      client.read_timeout = nil
    end
  rescue
    {nil, nil}
  end

  private def write_handshake(server : TCPSocket, dest_ip : String, dest_port : UInt16) : Void
    server.print "#{HANDSHAKE_PREFIX}#{dest_ip} #{dest_port}\n"
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

    2.times { channel.receive }
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
    puts "[relay] Listening on 0.0.0.0:#{@config.port}"

    loop do
      begin
        client = @server.accept
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
