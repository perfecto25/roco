require "socket"

class Netfilter
  CHAIN_NAME = "ROCO"

  def initialize(@listen_port : UInt16)
    @ipv4_targets = [] of String
    @ipv6_targets = [] of String
    @ipv4_exclusions = [] of String
    @ipv6_exclusions = [] of String
  end

  def add_target(target : String) : Void
    if ipv6?(target)
      @ipv6_targets << target
    elsif ipv4?(target)
      @ipv4_targets << target
    end
  end

  def add_exclusion(addr : String) : Void
    if ipv6?(addr)
      @ipv6_exclusions << addr
    elsif ipv4?(addr)
      @ipv4_exclusions << addr
    end
  end

  def setup : Void
    warn_if_not_root
    setup_family("iptables", @ipv4_exclusions, @ipv4_targets) unless @ipv4_targets.empty?
    setup_family("ip6tables", @ipv6_exclusions, @ipv6_targets) unless @ipv6_targets.empty?
  end

  def cleanup : Void
    cleanup_family("iptables")
    cleanup_family("ip6tables")
  end

  private def setup_family(cmd : String, exclusions : Array(String), targets : Array(String)) : Void
    puts "[netfilter] Setting up #{cmd} rules"
    run("#{cmd} -t nat -N #{CHAIN_NAME}", ignore_failure: true)
    run("#{cmd} -t nat -F #{CHAIN_NAME}")

    hook_chain(cmd, "OUTPUT")
    hook_chain(cmd, "PREROUTING")

    exclusions.each do |addr|
      puts "[netfilter] Exclusion: #{addr} (bypass)"
      run("#{cmd} -t nat -A #{CHAIN_NAME} -d #{addr} -j RETURN")
    end

    targets.each do |target|
      puts "[netfilter] Adding #{cmd} rule for #{target} -> local port #{@listen_port}"
      run("#{cmd} -t nat -A #{CHAIN_NAME} -p tcp -d #{target} -j REDIRECT --to-ports #{@listen_port}")
    end
  end

  private def hook_chain(cmd : String, parent : String) : Void
    return if system("#{cmd} -t nat -C #{parent} -j #{CHAIN_NAME} 2>/dev/null")
    run("#{cmd} -t nat -A #{parent} -j #{CHAIN_NAME}")
  end

  private def cleanup_family(cmd : String) : Void
    puts "[netfilter] Cleaning up #{cmd} chain #{CHAIN_NAME}"
    run("#{cmd} -t nat -D OUTPUT -j #{CHAIN_NAME}", ignore_failure: true)
    run("#{cmd} -t nat -D PREROUTING -j #{CHAIN_NAME}", ignore_failure: true)
    run("#{cmd} -t nat -F #{CHAIN_NAME}", ignore_failure: true)
    run("#{cmd} -t nat -X #{CHAIN_NAME}", ignore_failure: true)
  end

  private def run(command : String, ignore_failure : Bool = false) : Void
    status = system("#{command} 2>&1")
    unless status || ignore_failure
      puts "[netfilter] Command failed: #{command}"
    end
  end

  private def warn_if_not_root : Void
    if `id -u`.strip != "0"
      puts "[netfilter] WARNING: not running as root — iptables changes will fail"
    end
  rescue
  end

  private def ipv4?(target : String) : Bool
    target.includes?(".")
  end

  private def ipv6?(target : String) : Bool
    target.includes?(":") && !target.includes?(".")
  end
end
