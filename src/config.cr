require "yaml"
require "socket"

struct Relay
  getter name : String
  getter address : String
  getter port : UInt16
  getter targets : Array(String)

  def initialize(@name, @address, @port, @targets)
  end

  def resolve_address : String
    hostname = address.empty? ? name : address
    return hostname if /\A(\d{1,3}\.){3}\d{1,3}\z/.matches?(hostname)
    return hostname if hostname.includes?(":")
    Socket::Addrinfo.resolve(hostname, 0, type: Socket::Type::STREAM).first.ip_address.address
  rescue ex
    raise "Cannot resolve relay hostname '#{address.empty? ? name : address}': #{ex.message}"
  end

  def matches_destination?(dest_ip : String) : Bool
    targets.any? { |t| target_matches?(t, dest_ip) }
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
  getter relays : Hash(String, Relay)

  def initialize(@port = 12190_u16, @relays = {} of String => Relay)
  end

  def self.from_file(path : String) : Config
    yaml = YAML.parse(File.read(path))

    port = yaml["port"]?.try(&.as_i.to_u16) || 12190_u16

    relays = {} of String => Relay
    if relay_config = yaml["relays"]?
      relay_config.as_h.each do |name, config|
        relay_name = name.as_s
        relay_port = config["port"]?.try(&.as_i.to_u16) || port
        relay_address = config["address"]?.try(&.as_s) || ""

        targets = config["targets"]?.try(&.as_a.map(&.as_s)) || [] of String

        relays[relay_name] = Relay.new(relay_name, relay_address, relay_port, targets)
      end
    end

    new(port, relays)
  end

  def find_next_hop(dest_ip : String) : Relay?
    relays.each_value do |relay|
      return relay if relay.matches_destination?(dest_ip)
    end
    nil
  end

  def has_relays? : Bool
    !relays.empty?
  end
end
