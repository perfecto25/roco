require "./config"
require "./netfilter"
require "./proxy"

class Roco
  def initialize(config_path : String?)
    if config_path
      @config = Config.from_file(config_path)
    else
      @config = Config.new(port: 12190_u16)
    end
    @netfilter = Netfilter.new(@config.port)
  end

  def run : Void
    if @config.has_relays?
      install_netfilter_rules
    else
      puts "[roco] No relays configured — running as pure terminal/relay node"
    end

    puts "[roco] Starting listener on port #{@config.port}"
    server = RelayServer.new(@config)

    Signal::INT.trap { shutdown(server) }
    Signal::TERM.trap { shutdown(server) }

    server.start
  end

  private def install_netfilter_rules : Void
    puts "[roco] Configured relays: #{@config.relays.keys.join(", ")}"

    @config.relays.each do |name, relay|
      relay_addr = relay.resolve_address
      puts "[roco] Relay '#{name}' -> #{relay_addr}:#{relay.port}, targets: #{relay.targets.join(", ")}"

      @netfilter.add_exclusion(relay_addr)

      relay.targets.each do |target|
        @netfilter.add_target(target)
      end
    end

    @netfilter.setup
    puts "[roco] Netfilter rules installed"
  end

  private def shutdown(server : RelayServer) : Void
    puts "[roco] Shutting down..."
    @netfilter.cleanup
    server.close
    exit(0)
  end
end

# Main entry point
def show_help
  puts "Roco - Network Proxy Daemon for Relay Chains"
  puts ""
  puts "Roco enables an unreachable host to be accessed through a chain of reachable relays."
  puts "It operates at the network packet level using netfilter on Linux."
  puts ""
  puts "Every roco node runs the same listener. If relays are configured, iptables rules"
  puts "redirect matching local traffic into the listener, which forwards it to the next"
  puts "hop with an in-band destination header."
  puts ""
  puts "Usage:"
  puts "  roco [config_path]   # Run with config (installs iptables rules if relays defined)"
  puts "  roco --help          # Show this help message"
  puts "  roco                 # Run as terminal relay on default port 12190 (no iptables)"
  puts ""
  puts "Configuration File Example (YAML):"
  puts "---"
  puts "port: 12190"
  puts ""
  puts "relays:"
  puts "  serverB:"
  puts "    targets: [\"serverC\", \"208.224.251.1\", \"192.168.30.0/24\"]"
  puts "    port: 12255  # optional, overrides default"
  puts "  "
  puts "  serverD:"
  puts "    targets: [\"serverE\"]"
  puts "    # uses port 12190"
end

arg = ARGV[0]?

if arg == "--help" || arg == "-h"
  show_help
  exit(0)
end

config_path = arg

if config_path && !File.exists?(config_path)
  puts "Error: Config file not found at #{config_path}"
  puts "Usage: roco [config_path]"
  exit(1)
end

roco = Roco.new(config_path)
roco.run
