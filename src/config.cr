require "yaml"
require "socket"

struct Hop
  getter host : String
  getter port : UInt16

  def initialize(@host, @port)
  end

  # Parse "host:port", "[ipv6]:port", or "host" (with default port).
  def self.parse(s : String, default_port : UInt16) : Hop
    s = s.strip
    if s.starts_with?("[")
      close = s.index("]:")
      raise "Invalid hop format: #{s}" unless close
      Hop.new(s[1...close], s[(close + 2)..].to_u16)
    elsif idx = s.rindex(':')
      Hop.new(s[0...idx], s[(idx + 1)..].to_u16)
    else
      Hop.new(s, default_port)
    end
  end

  def to_handshake : String
    if host.includes?(":")
      "[#{host}]:#{port}"
    else
      "#{host}:#{port}"
    end
  end

  def resolve_address : String
    return host if /\A(\d{1,3}\.){3}\d{1,3}\z/.matches?(host)
    return host if host.includes?(":")
    Socket::Addrinfo.resolve(host, 0, type: Socket::Type::STREAM).first.ip_address.address
  rescue ex
    raise "Cannot resolve hop hostname '#{host}': #{ex.message}"
  end
end

struct Relay
  getter chain : Array(Hop)
  getter targets : Array(String)
  getter resolve_dns : Bool

  def initialize(@chain, @targets, @resolve_dns = false)
  end

  def matching_target(dest_ip : String) : String?
    targets.find { |t| target_matches?(t, dest_ip) }
  end

  def matches_destination?(dest_ip : String) : Bool
    !matching_target(dest_ip).nil?
  end

  private def target_matches?(target : String, dest_ip : String) : Bool
    if target.includes?("/")
      cidr_match?(target, dest_ip)
    else
      resolve_target(target) == dest_ip
    end
  rescue
    false
  end

  private def resolve_target(target : String) : String
    return target if /\A(\d{1,3}\.){3}\d{1,3}\z/.matches?(target)
    return target if target.includes?(":")
    Socket::Addrinfo.resolve(target, 0, type: Socket::Type::STREAM).first.ip_address.address
  rescue
    target
  end

  private def cidr_match?(cidr : String, dest_ip : String) : Bool
    parts = cidr.split("/")
    return false unless parts.size == 2
    prefix = parts[1].to_i
    return false if prefix < 0 || prefix > 32
    net_u32 = ipv4_to_u32(parts[0])
    ip_u32 = ipv4_to_u32(dest_ip)
    mask = prefix == 0 ? 0_u32 : (0xFFFFFFFF_u32 << (32 - prefix)).to_u32
    (net_u32 & mask) == (ip_u32 & mask)
  rescue
    false
  end

  private def ipv4_to_u32(ip : String) : UInt32
    octets = ip.split(".").map(&.to_u32)
    raise "Invalid IPv4: #{ip}" if octets.size != 4
    (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
  end
end

class Config
  getter port : UInt16
  getter relays : Array(Relay)
  getter log : String
  getter log_level : String
  getter firewall : String

  def initialize(@port = 12190_u16,
                 @relays = [] of Relay,
                 @log = "stdout",
                 @log_level = "info",
                 @firewall = "iptables")
  end

  def self.from_file(path : String) : Config
    yaml = YAML.parse(File.read(path))

    port = yaml["port"]?.try(&.as_i.to_u16) || 12190_u16
    log = yaml["log"]?.try(&.as_s) || "stdout"
    log_level = yaml["log_level"]?.try(&.as_s) || "info"
    firewall = yaml["firewall"]?.try(&.as_s) || "iptables"

    relays = [] of Relay
    if relay_config = yaml["relays"]?
      relay_config.as_a.each do |conf|
        targets = conf["targets"]?.try(&.as_a.map(&.as_s)) || [] of String
        chain = parse_chain(conf, port)
        resolve_dns = conf["resolve_dns"]?.try(&.as_bool) || false
        relays << Relay.new(chain, targets, resolve_dns)
      end
    end

    new(port, relays, log, log_level, firewall)
  end

  def find_route(dest_ip : String) : Tuple(Relay, String)?
    relays.each do |relay|
      if matched = relay.matching_target(dest_ip)
        return {relay, matched}
      end
    end
    nil
  end

  def has_relays? : Bool
    !relays.empty?
  end

  private def self.parse_chain(conf : YAML::Any, default_port : UInt16) : Array(Hop)
    if chain_yaml = conf["chain"]?
      chain_yaml.as_a.map do |entry|
        if str = entry.as_s?
          Hop.parse(str, default_port)
        else
          host = entry["host"].as_s
          port = entry["port"]?.try(&.as_i.to_u16) || default_port
          Hop.new(host, port)
        end
      end
    else
      [] of Hop
    end
  end
end
