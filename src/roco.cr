require "./config"
require "./netfilter"
require "./proxy"
require "./logger"

class Roco
  def initialize(config_path : String?)
    if config_path
      @config = Config.from_file(config_path)
    else
      @config = Config.new(port: 12190_u16)
    end
    Logger.configure(@config.log, @config.log_level)
    @netfilter = Netfilter.new(@config.port)
  end

  def run : Void
    if @config.has_relays?
      install_netfilter_rules
    else
      Logger.info("roco", "No relays configured — running as pure terminal/relay node")
    end

    Logger.info("roco", "Starting listener on port #{@config.port}")
    server = RelayServer.new(@config)

    Signal::INT.trap { shutdown(server) }
    Signal::TERM.trap { shutdown(server) }

    server.start
  end

  private def install_netfilter_rules : Void
    Logger.info("roco", "Installing #{@config.relays.size} relay rule(s)")

    @config.relays.each_with_index do |relay, i|
      chain_desc = relay.chain.map { |h| "#{h.host}:#{h.port}" }.join(" -> ")
      Logger.info("roco", "Rule #{i + 1}: chain=#{chain_desc}, targets=#{relay.targets.join(", ")}")

      first_addr = relay.chain.first.resolve_address
      @netfilter.add_exclusion(first_addr)

      relay.targets.each { |target| @netfilter.add_target(target) }
    end

    @netfilter.setup
    Logger.info("roco", "Netfilter rules installed")
  end

  private def shutdown(server : RelayServer) : Void
    Logger.info("roco", "Shutting down...")
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
  puts "  roco -c <config_path>   # Run with the given config file"
  puts "  roco                    # Use /etc/roco/config.yaml if present,"
  puts "                          # otherwise run as terminal relay on default port 12190"
  puts "  roco --help             # Show this help message"
  puts ""
  puts "Configuration File Example (YAML):"
  puts "---"
  puts "port: 12190"
  puts "log: stdout         # or /path/to/logfile"
  puts "log_level: info     # or debug"
  puts ""
  puts "relays:"
  puts "  - targets: [\"serverC\", \"208.224.251.1\", \"192.168.30.0/24\"]"
  puts "    chain: [hostB]"
  puts ""
  puts "  # Multi-hop chain: A -> B -> C -> D -> E -> F"
  puts "  # resolve_dns: true passes the hostname through so each hop resolves it locally."
  puts "  - targets: [\"F\"]"
  puts "    chain: [B, C, D, E]"
  puts "    resolve_dns: true"
end

DEFAULT_CONFIG_PATH = "/etc/roco/config.yaml"

config_path = nil.as(String?)
explicit_config = false

i = 0
while i < ARGV.size
  arg = ARGV[i]
  case arg
  when "--help", "-h"
    show_help
    exit(0)
  when "-c", "--config"
    next_arg = ARGV[i + 1]?
    unless next_arg
      puts "Error: #{arg} requires a path argument"
      exit(1)
    end
    config_path = next_arg
    explicit_config = true
    i += 2
    next
  else
    puts "Error: Unknown argument: #{arg}"
    puts "Run 'roco --help' for usage."
    exit(1)
  end
  i += 1
end

if explicit_config
  unless config_path && File.exists?(config_path)
    puts "Error: Config file not found at #{config_path}"
    exit(1)
  end
elsif File.exists?(DEFAULT_CONFIG_PATH)
  config_path = DEFAULT_CONFIG_PATH
  puts "[roco] Using config #{DEFAULT_CONFIG_PATH}"
else
  puts "[roco] No config provided and #{DEFAULT_CONFIG_PATH} not found — running in relay mode on default port"
  config_path = nil
end

roco = Roco.new(config_path)
roco.run
