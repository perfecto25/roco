require "./pki"

# `roco tls <command>` — certificate management for the roco mTLS links.
#
# Admin machine (holds the CA):  init-ca, issue, sign
# Relay node:                    request
# Anywhere:                      show
module TlsCli
  DEFAULT_NODE_DIR = "/etc/roco/tls"

  class Options
    property dir : String? = nil
    property days : Int32? = nil
    property name : String? = nil
    property force = false
    property dns = [] of String
    property ips = [] of String
    property args = [] of String
  end

  def self.run(argv : Array(String)) : Nil
    command = argv.first?
    if command.nil? || {"-h", "--help", "help"}.includes?(command)
      usage
      exit(command.nil? ? 1 : 0)
    end

    opts = parse(argv[1..])
    case command
    when "init-ca" then init_ca(opts)
    when "issue"   then issue(opts)
    when "request" then request(opts)
    when "sign"    then sign(opts)
    when "show"    then show(opts)
    else
      fail "Unknown tls command: #{command}. Run 'roco tls --help'."
    end
  rescue ex : PKI::Error | OpenSSL::Error | File::Error
    fail ex.message || ex.class.name
  end

  def self.usage : Nil
    puts <<-TEXT
    Usage: roco tls <command> [options]

    On the admin machine (keeps the CA private key):
      init-ca                     Create the CA (ca.key, ca.crt)
      issue <node>                Generate a key + certificate for a node in one step
      sign <node.csr>             Sign a request made on a node with 'roco tls request'

    On a relay node:
      request <node>              Generate node.key and <node>.csr (key never leaves the node)

    Anywhere:
      show <file.crt>             Print a certificate (subject, SANs, validity)

    Options:
      --dir DIR                   CA directory for init-ca/issue/sign (default: current dir)
                                  Output directory for request (default: #{DEFAULT_NODE_DIR})
      --ip IP                     Extra IP address for the node certificate (repeatable)
      --dns NAME                  Extra DNS name for the node certificate (repeatable)
      --days N                    Validity in days (CA: #{PKI::CA_DAYS}, node: #{PKI::NODE_DAYS})
      --name NAME                 CA common name for init-ca (default: "roco CA")
      --force                     Overwrite existing files

    The node name is always included in the certificate. It must match how other
    nodes refer to this node in their `chain:` config (hostname or IP); add every
    other name/IP they might use with --dns/--ip.
    TEXT
  end

  # --- Commands -----------------------------------------------------------

  private def self.init_ca(opts : Options) : Nil
    dir = opts.dir || "."
    key_path = File.join(dir, PKI::CA_KEY)
    cert_path = File.join(dir, PKI::CA_CERT)
    ensure_writable(key_path, opts.force)
    ensure_writable(cert_path, opts.force)

    name = opts.name || "roco CA"
    days = opts.days || PKI::CA_DAYS
    key, cert = PKI.create_ca(name, days)

    Dir.mkdir_p(dir)
    write_secret(key_path, key.to_pem)
    File.write(cert_path, cert.to_pem)

    puts "Created CA \"#{name}\" (valid #{days} days)"
    puts "  #{key_path}   PRIVATE - keep on this machine only, back it up"
    puts "  #{cert_path}   public - copied to every node"
    puts ""
    puts "Next: roco tls issue <node> --ip <node-ip>   (or 'roco tls request' on the node)"
  end

  private def self.issue(opts : Options) : Nil
    name = node_name_arg(opts)
    ca_dir = opts.dir || "."
    ca_key, ca_cert = load_ca(ca_dir)
    out_dir = node_out_dir(ca_dir, name)
    key_path = File.join(out_dir, PKI::NODE_KEY)
    ensure_writable(key_path, opts.force)
    ensure_writable(File.join(out_dir, PKI::NODE_CERT), opts.force)

    sans = PKI.subject_alt_names(name, opts.dns, opts.ips)
    days = opts.days || PKI::NODE_DAYS
    key = PKI::Key.generate
    cert = PKI.issue(ca_key, ca_cert, name, key.handle, sans, days)

    Dir.mkdir_p(out_dir)
    write_secret(key_path, key.to_pem)
    write_node_bundle(out_dir, cert, ca_dir)

    puts "Issued certificate for #{name} (valid #{days} days)"
    puts "  names: #{sans.join(", ")}"
    puts "  #{out_dir}/"
    puts "    #{PKI::NODE_KEY}   PRIVATE"
    puts "    #{PKI::NODE_CERT}"
    puts "    #{PKI::CA_CERT}"
    puts ""
    puts "Copy all three to #{DEFAULT_NODE_DIR}/ on #{name}, e.g.:"
    puts "  ssh #{name} mkdir -p #{DEFAULT_NODE_DIR}"
    puts "  scp #{out_dir}/* #{name}:#{DEFAULT_NODE_DIR}/"
    puts "  ssh #{name} chmod 600 #{DEFAULT_NODE_DIR}/#{PKI::NODE_KEY}"
  end

  private def self.request(opts : Options) : Nil
    name = node_name_arg(opts)
    dir = opts.dir || DEFAULT_NODE_DIR
    key_path = File.join(dir, PKI::NODE_KEY)
    csr_path = File.join(dir, "#{name}.csr")
    ensure_writable(key_path, opts.force)
    ensure_writable(csr_path, opts.force)

    key = PKI::Key.generate
    req = PKI.create_request(name, key)

    Dir.mkdir_p(dir)
    write_secret(key_path, key.to_pem)
    File.write(csr_path, req.to_pem)

    puts "Created key and signing request for #{name}"
    puts "  #{key_path}   PRIVATE - stays on this node"
    puts "  #{csr_path}"
    puts ""
    puts "Next: copy #{name}.csr to the admin machine and run"
    puts "  roco tls sign #{name}.csr --ip <this-node-ip>"
  end

  private def self.sign(opts : Options) : Nil
    csr_path = opts.args.first? || fail("Usage: roco tls sign <node.csr> [--ip IP] [--dns NAME]")
    ca_dir = opts.dir || "."
    ca_key, ca_cert = load_ca(ca_dir)

    req = PKI::Request.load(csr_path)
    name = req.common_name || fail("#{csr_path} has no common name")
    fail "Invalid node name in CSR: #{name}" unless PKI.valid_name?(name)
    out_dir = node_out_dir(ca_dir, name)
    ensure_writable(File.join(out_dir, PKI::NODE_CERT), opts.force)

    sans = PKI.subject_alt_names(name, opts.dns, opts.ips)
    days = opts.days || PKI::NODE_DAYS
    pubkey = PKI.request_pubkey(req)
    begin
      cert = PKI.issue(ca_key, ca_cert, name, pubkey, sans, days)
    ensure
      LibCrypto.evp_pkey_free(pubkey)
    end

    Dir.mkdir_p(out_dir)
    write_node_bundle(out_dir, cert, ca_dir)

    puts "Signed certificate for #{name} (valid #{days} days)"
    puts "  names: #{sans.join(", ")}"
    puts "  #{out_dir}/#{PKI::NODE_CERT}"
    puts "  #{out_dir}/#{PKI::CA_CERT}"
    puts ""
    puts "Copy both to #{DEFAULT_NODE_DIR}/ on #{name} (next to its node.key), e.g.:"
    puts "  scp #{out_dir}/#{PKI::NODE_CERT} #{out_dir}/#{PKI::CA_CERT} #{name}:#{DEFAULT_NODE_DIR}/"
  end

  private def self.show(opts : Options) : Nil
    path = opts.args.first? || fail("Usage: roco tls show <file.crt>")
    puts PKI::Certificate.load(path).to_text
  end

  # --- Helpers ------------------------------------------------------------

  private def self.parse(args : Array(String)) : Options
    opts = Options.new
    i = 0
    while i < args.size
      arg = args[i]
      case arg
      when "--force"
        opts.force = true
      when "--dir", "--days", "--name", "--ip", "--dns"
        value = args[i + 1]? || fail("#{arg} requires a value")
        i += 1
        case arg
        when "--dir"  then opts.dir = value
        when "--name" then opts.name = value
        when "--days"
          days = value.to_i? || fail("--days must be a number")
          fail("--days must be positive") unless days > 0
          opts.days = days
        when "--ip"  then opts.ips.concat(split_list(value))
        when "--dns" then opts.dns.concat(split_list(value))
        end
      else
        fail("Unknown option: #{arg}") if arg.starts_with?("--")
        opts.args << arg
      end
      i += 1
    end
    opts
  end

  private def self.split_list(value : String) : Array(String)
    value.split(',').map(&.strip).reject(&.empty?)
  end

  private def self.node_name_arg(opts : Options) : String
    name = opts.args.first? || fail("A node name is required, e.g. 'atlas' or '192.168.40.21'")
    fail "Invalid node name: #{name}" unless PKI.valid_name?(name)
    name
  end

  private def self.node_out_dir(ca_dir : String, name : String) : String
    File.join(ca_dir, "nodes", name)
  end

  private def self.load_ca(dir : String) : {PKI::Key, PKI::Certificate}
    key_path = File.join(dir, PKI::CA_KEY)
    cert_path = File.join(dir, PKI::CA_CERT)
    unless File.exists?(key_path) && File.exists?(cert_path)
      fail "No CA found in #{File.expand_path(dir)} (need #{PKI::CA_KEY} and #{PKI::CA_CERT}). " \
           "Run 'roco tls init-ca' first, or pass --dir."
    end
    key = PKI::Key.load(key_path)
    cert = PKI::Certificate.load(cert_path)
    fail "#{key_path} does not match #{cert_path}" unless cert.matches_key?(key)
    {key, cert}
  end

  # Node bundle: its cert plus the CA cert file as-is, so a CA bundle holding
  # several CAs (during CA rotation) is passed through intact.
  private def self.write_node_bundle(out_dir : String, cert : PKI::Certificate, ca_dir : String) : Nil
    File.write(File.join(out_dir, PKI::NODE_CERT), cert.to_pem)
    File.copy(File.join(ca_dir, PKI::CA_CERT), File.join(out_dir, PKI::CA_CERT))
  end

  private def self.ensure_writable(path : String, force : Bool) : Nil
    if File.exists?(path) && !force
      fail "#{path} already exists (use --force to overwrite)"
    end
  end

  private def self.write_secret(path : String, content : String) : Nil
    File.write(path, content, perm: 0o600)
    File.chmod(path, 0o600) # perm only applies when the file is created
  end

  private def self.fail(message : String) : NoReturn
    STDERR.puts "Error: #{message}"
    exit(1)
  end
end
