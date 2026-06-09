require "socket"
require "./logger"

class Netfilter
  CHAIN_NAME = "ROCO"

  def initialize(@listen_port : UInt16, @firewall : String = "iptables")
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
    if @firewall == "nftables"
      setup_family_nft("ip", "ip", @ipv4_exclusions, @ipv4_targets) unless @ipv4_targets.empty?
      setup_family_nft("ip6", "ip6", @ipv6_exclusions, @ipv6_targets) unless @ipv6_targets.empty?
    else
      setup_family("iptables", @ipv4_exclusions, @ipv4_targets) unless @ipv4_targets.empty?
      setup_family("ip6tables", @ipv6_exclusions, @ipv6_targets) unless @ipv6_targets.empty?
    end
  end

  def cleanup : Void
    if @firewall == "nftables"
      cleanup_family_nft("ip")
      cleanup_family_nft("ip6")
    else
      cleanup_family("iptables")
      cleanup_family("ip6tables")
    end
  end

  # ── iptables ──────────────────────────────────────────────────────────────

  private def setup_family(cmd : String, exclusions : Array(String), targets : Array(String)) : Void
    Logger.info("netfilter", "Setting up #{cmd} rules")
    run("#{cmd} -t nat -N #{CHAIN_NAME}", ignore_failure: true)
    run("#{cmd} -t nat -F #{CHAIN_NAME}")

    hook_chain(cmd, "OUTPUT")
    hook_chain(cmd, "PREROUTING")

    exclusions.each do |addr|
      Logger.debug("netfilter", "Exclusion: #{addr} (bypass)")
      run("#{cmd} -t nat -A #{CHAIN_NAME} -d #{addr} -j RETURN")
    end

    targets.each do |target|
      Logger.info("netfilter", "Adding #{cmd} rule for #{target} -> local port #{@listen_port}")
      run("#{cmd} -t nat -A #{CHAIN_NAME} -p tcp -d #{target} -j REDIRECT --to-ports #{@listen_port}")
    end
  end

  private def hook_chain(cmd : String, parent : String) : Void
    return if system("#{cmd} -t nat -C #{parent} -j #{CHAIN_NAME} 2>/dev/null")
    run("#{cmd} -t nat -A #{parent} -j #{CHAIN_NAME}")
  end

  private def cleanup_family(cmd : String) : Void
    Logger.info("netfilter", "Cleaning up #{cmd} chain #{CHAIN_NAME}")
    run("#{cmd} -t nat -D OUTPUT -j #{CHAIN_NAME}", ignore_failure: true)
    run("#{cmd} -t nat -D PREROUTING -j #{CHAIN_NAME}", ignore_failure: true)
    run("#{cmd} -t nat -F #{CHAIN_NAME}", ignore_failure: true)
    run("#{cmd} -t nat -X #{CHAIN_NAME}", ignore_failure: true)
  end

  # ── nftables ──────────────────────────────────────────────────────────────

  private def setup_family_nft(family : String, addr_keyword : String, exclusions : Array(String), targets : Array(String)) : Void
    Logger.info("netfilter", "Setting up nftables rules (#{family})")

    # "tcp" alone is not a valid nftables expression; must reference a header field.
    proto_match = family == "ip6" ? "ip6 nexthdr tcp" : "ip protocol tcp"

    # Start fresh: delete the table if it exists, then recreate it.
    run("nft delete table #{family} #{CHAIN_NAME}", ignore_failure: true)
    run("nft add table #{family} #{CHAIN_NAME}")
    run("nft add chain #{family} #{CHAIN_NAME} PREROUTING '{ type nat hook prerouting priority dstnat; policy accept; }'")
    run("nft add chain #{family} #{CHAIN_NAME} OUTPUT '{ type nat hook output priority -100; policy accept; }'")

    exclusions.each do |addr|
      Logger.debug("netfilter", "Exclusion: #{addr} (bypass)")
      run("nft add rule #{family} #{CHAIN_NAME} PREROUTING #{addr_keyword} daddr #{addr} return")
      run("nft add rule #{family} #{CHAIN_NAME} OUTPUT #{addr_keyword} daddr #{addr} return")
    end

    targets.each do |target|
      Logger.info("netfilter", "Adding nftables rule for #{target} -> local port #{@listen_port}")
      run("nft add rule #{family} #{CHAIN_NAME} PREROUTING #{addr_keyword} daddr #{target} #{proto_match} redirect to :#{@listen_port}")
      run("nft add rule #{family} #{CHAIN_NAME} OUTPUT #{addr_keyword} daddr #{target} #{proto_match} redirect to :#{@listen_port}")
    end
  end

  private def cleanup_family_nft(family : String) : Void
    Logger.info("netfilter", "Cleaning up nftables table #{family} #{CHAIN_NAME}")
    run("nft delete table #{family} #{CHAIN_NAME}", ignore_failure: true)
  end

  # ── shared ────────────────────────────────────────────────────────────────

  private def run(command : String, ignore_failure : Bool = false) : Void
    status = system("#{command} 2>&1")
    unless status || ignore_failure
      Logger.error("netfilter", "Command failed: #{command}")
    end
  end

  private def warn_if_not_root : Void
    if `id -u`.strip != "0"
      tool = @firewall == "nftables" ? "nftables" : "iptables"
      Logger.warn("netfilter", "Not running as root — #{tool} changes will fail")
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
