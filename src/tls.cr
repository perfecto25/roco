require "openssl"
require "socket"
require "./logger"
require "./pki"

# Mutual TLS between roco nodes. Only peer links (roco -> roco) are encrypted;
# locally redirected app traffic and the final hop to the real target stay
# plain TCP, since neither end of those speaks roco.
class Tls
  enum Mode
    Off      # plaintext in and out
    Optional # dial peers with TLS, accept TLS or plaintext (for rollout)
    Required # TLS only, both directions
  end

  TLS1_3_VERSION                 = 0x0304
  SSL_CTRL_SET_MIN_PROTO_VERSION =    123
  # First byte of a TLS record carrying a handshake message (ClientHello).
  TLS_HANDSHAKE_RECORD = 0x16_u8

  HANDSHAKE_TIMEOUT = 10.seconds

  getter mode : Mode
  getter cert_name : String?

  def initialize(@mode : Mode, ca : String, cert : String, key : String, @allowed_peers : Array(String))
    @server_ctx = nil.as(OpenSSL::SSL::Context::Server?)
    @client_ctx = nil.as(OpenSSL::SSL::Context::Client?)
    return if @mode.off?

    {ca => "ca", cert => "cert", key => "key"}.each do |path, field|
      unless File.exists?(path)
        raise "TLS #{field} file not found: #{path} (see 'roco tls --help')"
      end
    end

    @cert_name = PKI::Certificate.load(cert).common_name
    @server_ctx = build_server_context(ca, cert, key)
    @client_ctx = build_client_context(ca, cert, key)
  end

  # Wrap an incoming peer connection according to the mode. Returns the IO to
  # talk to the peer through, plus the peer's certificate name (nil = plain).
  def accept(tcp : TCPSocket) : {IO, String?}
    case @mode
    in .off?
      {tcp, nil}
    in .required?
      # Peek first so a plaintext (or pre-TLS roco) peer gets a clear log line
      # instead of an opaque OpenSSL record error.
      raise "Plaintext peer connection rejected (tls mode: required)" unless tls_client_hello?(tcp)
      server_handshake(tcp)
    in .optional?
      tls_client_hello?(tcp) ? server_handshake(tcp) : {tcp, nil}
    end
  end

  # Wrap an outgoing connection to the next roco hop. `host` is the name the
  # hop is configured under; its certificate must carry it as a SAN.
  def connect(tcp : TCPSocket, host : String) : IO
    ctx = @client_ctx
    return tcp unless ctx
    with_timeout(tcp) do
      OpenSSL::SSL::Socket::Client.new(tcp, ctx, sync_close: true, hostname: host)
    end
  rescue ex : OpenSSL::Error
    raise "TLS handshake with #{host} failed: #{ex.message}"
  end

  private def server_handshake(tcp : TCPSocket) : {IO, String?}
    ctx = @server_ctx.not_nil!
    ssl = with_timeout(tcp) do
      OpenSSL::SSL::Socket::Server.new(tcp, ctx, sync_close: true)
    end
    name = peer_name(ssl)
    unless @allowed_peers.empty? || @allowed_peers.includes?(name)
      ssl.close rescue nil
      raise "TLS peer '#{name}' is not in allowed_peers"
    end
    {ssl, name}
  rescue ex : OpenSSL::Error
    raise "TLS handshake failed: #{ex.message}"
  end

  private def tls_client_hello?(tcp : TCPSocket) : Bool
    with_timeout(tcp) do
      buf = tcp.peek
      !buf.nil? && !buf.empty? && buf[0] == TLS_HANDSHAKE_RECORD
    end
  end

  private def peer_name(ssl : OpenSSL::SSL::Socket) : String
    cert = ssl.peer_certificate
    cn = cert.try &.subject.to_a.find { |(k, _)| k == "CN" }
    cn ? cn[1] : "unknown"
  end

  private def with_timeout(tcp : TCPSocket, &)
    tcp.read_timeout = HANDSHAKE_TIMEOUT
    begin
      yield
    ensure
      tcp.read_timeout = nil
    end
  end

  # Both contexts start from `insecure` (a bare SSL_CTX) rather than `new`,
  # which would also trust the system CA store; peers must be signed by the
  # roco CA only.
  private def build_server_context(ca : String, cert : String, key : String) : OpenSSL::SSL::Context::Server
    ctx = OpenSSL::SSL::Context::Server.insecure
    harden(ctx, ca, cert, key)
    set_verify_purpose(ctx, "ssl_client")
    ctx.verify_mode = OpenSSL::SSL::VerifyMode::PEER | OpenSSL::SSL::VerifyMode::FAIL_IF_NO_PEER_CERT
    ctx.disable_session_resume_tickets
    ctx
  end

  private def build_client_context(ca : String, cert : String, key : String) : OpenSSL::SSL::Context::Client
    ctx = OpenSSL::SSL::Context::Client.insecure
    harden(ctx, ca, cert, key)
    set_verify_purpose(ctx, "ssl_server")
    ctx.verify_mode = OpenSSL::SSL::VerifyMode::PEER
    ctx
  end

  # Require the peer certificate to be valid for its role (serverAuth /
  # clientAuth). Same as Context#default_verify_param=, which Crystal 1.18
  # wrongly reports as unimplemented (it checks LibSSL for a LibCrypto fun).
  private def set_verify_purpose(ctx : OpenSSL::SSL::Context, name : String) : Nil
    param = LibCrypto.x509_verify_param_lookup(name)
    raise "Unsupported verify param #{name}" unless param
    raise OpenSSL::Error.new("SSL_CTX_set1_param") unless LibSSL.ssl_ctx_set1_param(ctx, param) == 1
  end

  private def harden(ctx : OpenSSL::SSL::Context, ca : String, cert : String, key : String) : Nil
    # Every peer is a roco node, so there is no legacy client to support.
    LibSSL.ssl_ctx_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, LibC::ULong.new(TLS1_3_VERSION), nil)
    ctx.add_options(OpenSSL::SSL::Options.flags(ALL, NO_RENEGOTIATION))
    # Kernel TLS can't start once we've peeked at the first bytes (they sit in
    # the userspace read buffer); stdlib's non-insecure contexts disable it too.
    {% if OpenSSL.has_constant?(:KTLS) %}
      ctx.remove_options(OpenSSL::SSL::Options::ENABLE_KTLS)
    {% end %}
    ctx.ca_certificates = ca
    ctx.certificate_chain = cert
    ctx.private_key = key # also checks the key matches the certificate
  end
end
