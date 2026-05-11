require "socket"

lib LibC
  SO_ORIGINAL_DST = 80
end

class SocketUtils
  def self.get_original_destination(socket : TCPSocket) : {String?, UInt16?}
    fd = socket.fd

    # SO_ORIGINAL_DST only works when DNAT happened on THIS host.
    # If it fails, do NOT fall back to local_address — that loops the relay
    # into connecting to itself.
    result = get_original_destination_ipv4(fd)
    ip = result[0]
    port = result[1]
    return {nil, nil} unless ip && port

    begin
      local_addr = socket.local_address
      if ip == local_addr.address && port == local_addr.port.to_u16
        return {nil, nil}
      end
    rescue
    end
    {ip, port}
  end

  private def self.get_original_destination_ipv4(fd : Int) : {String?, UInt16?}
    # SO_ORIGINAL_DST is Linux-specific and returns the original destination
    # of a redirected packet. This requires raw socket operations.
    # For now, we'll use a fallback approach with netfilter user-space tools
    # or simply the socket's local address (which is where it was redirected to).

    begin
      # Create a sockaddr_in buffer
      sockaddr = Bytes.new(16)
      socklen = LibC::SocklenT.new(16)

      # getsockopt call to retrieve SO_ORIGINAL_DST
      result = LibC.getsockopt(fd, 0, LibC::SO_ORIGINAL_DST.to_i, sockaddr.to_unsafe, pointerof(socklen))

      if result == 0 && socklen >= 8
        # Parse sockaddr_in: sin_family (2 bytes), sin_port (2 bytes), sin_addr (4 bytes)
        port_bytes = sockaddr[2, 2]
        port = (port_bytes[0].to_u16 << 8) | port_bytes[1].to_u16

        addr_bytes = sockaddr[4, 4]
        ip = "#{addr_bytes[0]}.#{addr_bytes[1]}.#{addr_bytes[2]}.#{addr_bytes[3]}"

        {ip, port}
      else
        {nil, nil}
      end
    rescue
      {nil, nil}
    end
  end
end
