require "./config"
require "./netfilter"
require "./proxy"
require "./logger"
require "./tls"
require "./tls_cli"

VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}

class Roco
  @tls : Tls

  def initialize(config_path : String?)
    if config_path
      @config = Config.from_file(config_path)
    else
      @config = Config.new(port: 12190_u16)
    end
    Logger.configure(@config.log, @config.log_level)
    @netfilter = Netfilter.new(@config.port, @config.firewall)
    @tls = load_tls
  end

  def run : Void
    if @config.has_relays?
      install_netfilter_rules
    else
      Logger.info("roco", "No relays configured — running as pure terminal/relay node")
    end

    Logger.info("roco", "Starting listener on port #{@config.port}")
    server = RelayServer.new(@config, @tls)

    Signal::INT.trap { shutdown(server) }
    Signal::TERM.trap { shutdown(server) }

    server.start
  end

  private def load_tls : Tls
    t = @config.tls
    tls = Tls.new(t.mode, t.ca, t.cert, t.key, t.allowed_peers)
    if tls.mode.off?
      Logger.info("roco", "TLS off — peer links are unencrypted")
    else
      peers = t.allowed_peers.empty? ? "any node signed by the CA" : t.allowed_peers.join(", ")
      Logger.info("roco", "TLS #{tls.mode.to_s.downcase}, node certificate #{tls.cert_name} (#{t.cert}), accepting #{peers}")
    end
    tls
  rescue e
    Logger.error("roco", "TLS setup failed: #{e.message}")
    exit(1)
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
  #ERSION    = SHARD_YML.lines.find { |l| l.starts_with?("version:") }.not_nil!.split(": ", 2).last.strip
  puts "Roco (#{VERSION}) - Network Proxy Daemon for Relay Chains"
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
  puts "  roco tls <command>      # Manage TLS certificates (see 'roco tls --help')"
  puts "  roco --help             # Show this help message"
  puts ""
  puts "Configuration File Example (YAML):"
  puts "---"
  puts "port: 12190"
  puts "firewall: iptables  # or nftables"
  puts "log: stdout         # or /path/to/logfile"
  puts "log_level: info     # or debug"
  puts ""
  puts "tls:                # encrypt roco-to-roco links (mutual TLS)"
  puts "  mode: required    # off (default) | optional | required"
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

if ARGV.first? == "tls"
  TlsCli.run(ARGV[1..])
  exit(0)
end

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
