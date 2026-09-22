require "openssl"
require "socket"

# Extra libcrypto bindings for generating keys, CSRs and certificates. The
# stdlib covers the TLS side and parts of X509 reading, but not issuance. This
# reopens stdlib's LibCrypto (reusing its X509/X509_NAME/Bio types and link
# setup) and adds only what is missing; key, request and bignum handles are
# plain Void* since stdlib has no types for them. Functions stdlib already
# binds are called through its bindings, and only ones whose signature is the
# same across Crystal versions (1.18 binds fewer than later releases).
lib LibCrypto
  ROCO_EVP_PKEY_ED25519 =   1087
  ROCO_NID_COMMON_NAME  =     13
  ROCO_MBSTRING_ASC     = 0x1001

  fun evp_pkey_ctx_new_id = EVP_PKEY_CTX_new_id(id : Int, e : Void*) : Void*
  fun evp_pkey_ctx_free = EVP_PKEY_CTX_free(ctx : Void*)
  fun evp_pkey_keygen_init = EVP_PKEY_keygen_init(ctx : Void*) : Int
  fun evp_pkey_keygen = EVP_PKEY_keygen(ctx : Void*, ppkey : Void**) : Int
  fun evp_pkey_free = EVP_PKEY_free(pkey : Void*)

  fun bio_s_mem = BIO_s_mem : BioMethod*
  fun bio_new_mem_buf = BIO_new_mem_buf(buf : UInt8*, len : Int) : Bio*
  fun bio_ctrl_pending = BIO_ctrl_pending(b : Bio*) : SizeT
  fun bio_read = BIO_read(b : Bio*, data : Void*, dlen : Int) : Int

  fun pem_write_bio_private_key = PEM_write_bio_PrivateKey(bio : Bio*, pkey : Void*, enc : Void*, kstr : UInt8*, klen : Int, cb : Void*, u : Void*) : Int
  fun pem_read_bio_private_key = PEM_read_bio_PrivateKey(bio : Bio*, x : Void*, cb : Void*, u : Void*) : Void*
  fun pem_write_bio_x509 = PEM_write_bio_X509(bio : Bio*, x : X509) : Int
  fun pem_read_bio_x509 = PEM_read_bio_X509(bio : Bio*, x : Void*, cb : Void*, u : Void*) : X509
  fun pem_write_bio_x509_req = PEM_write_bio_X509_REQ(bio : Bio*, x : Void*) : Int
  fun pem_read_bio_x509_req = PEM_read_bio_X509_REQ(bio : Bio*, x : Void*, cb : Void*, u : Void*) : Void*

  fun bn_new = BN_new : Void*
  fun bn_free = BN_free(a : Void*)
  fun bn_rand = BN_rand(rnd : Void*, bits : Int, top : Int, bottom : Int) : Int
  fun bn_to_asn1_integer = BN_to_ASN1_INTEGER(bn : Void*, ai : Void*) : Void*

  fun x509_set_version = X509_set_version(x : X509, version : Long) : Int
  fun x509_get_serial_number = X509_get_serialNumber(x : X509) : Void*
  fun x509_getm_not_before = X509_getm_notBefore(x : X509) : Void*
  fun x509_getm_not_after = X509_getm_notAfter(x : X509) : Void*
  fun x509_gmtime_adj = X509_gmtime_adj(s : Void*, adj : Long) : Void*
  fun x509_set_pubkey = X509_set_pubkey(x : X509, pkey : Void*) : Int
  fun x509_set_issuer_name = X509_set_issuer_name(x : X509, name : X509_NAME) : Int
  fun x509_sign = X509_sign(x : X509, pkey : Void*, md : Void*) : Int
  fun x509_check_private_key = X509_check_private_key(x : X509, pkey : Void*) : Int
  fun x509_print_ex = X509_print_ex(bio : Bio*, x : X509, nmflag : ULong, cflag : ULong) : Int
  fun x509_name_get_text_by_nid = X509_NAME_get_text_by_NID(name : X509_NAME, nid : Int, buf : UInt8*, len : Int) : Int

  fun x509_req_new = X509_REQ_new : Void*
  fun x509_req_free = X509_REQ_free(req : Void*)
  fun x509_req_set_subject_name = X509_REQ_set_subject_name(req : Void*, name : X509_NAME) : Int
  fun x509_req_get_subject_name = X509_REQ_get_subject_name(req : Void*) : X509_NAME
  fun x509_req_set_pubkey = X509_REQ_set_pubkey(req : Void*, pkey : Void*) : Int
  fun x509_req_get_pubkey = X509_REQ_get_pubkey(req : Void*) : Void*
  fun x509_req_sign = X509_REQ_sign(req : Void*, pkey : Void*, md : Void*) : Int
  fun x509_req_verify = X509_REQ_verify(req : Void*, pkey : Void*) : Int

  fun x509v3_set_ctx = X509V3_set_ctx(ctx : Void*, issuer : X509, subject : X509, req : Void*, crl : Void*, flags : Int)
end

# Certificate authority tooling behind `roco tls ...`: an Ed25519 private CA
# that signs one certificate per roco node. Node certs carry both serverAuth and
# clientAuth since every node accepts peers and dials the next hop.
module PKI
  class Error < Exception
  end

  CA_KEY  = "ca.key"
  CA_CERT = "ca.crt"

  NODE_KEY  = "node.key"
  NODE_CERT = "node.crt"

  CA_DAYS   = 3650
  NODE_DAYS =  825

  # --- Key / cert / request wrappers --------------------------------------

  class Key
    getter handle : Void*

    def initialize(@handle)
    end

    def self.generate : Key
      ctx = LibCrypto.evp_pkey_ctx_new_id(LibCrypto::ROCO_EVP_PKEY_ED25519, nil)
      raise OpenSSL::Error.new("EVP_PKEY_CTX_new_id") if ctx.null?
      begin
        raise OpenSSL::Error.new("EVP_PKEY_keygen_init") unless LibCrypto.evp_pkey_keygen_init(ctx) == 1
        pkey = Pointer(Void).null
        raise OpenSSL::Error.new("EVP_PKEY_keygen") unless LibCrypto.evp_pkey_keygen(ctx, pointerof(pkey)) == 1
        new(pkey)
      ensure
        LibCrypto.evp_pkey_ctx_free(ctx)
      end
    end

    def self.load(path : String) : Key
      pkey = PKI.read_pem(path) { |bio| LibCrypto.pem_read_bio_private_key(bio, nil, nil, nil) }
      new(pkey)
    end

    def to_pem : String
      PKI.write_pem { |bio| LibCrypto.pem_write_bio_private_key(bio, @handle, nil, nil, 0, nil, nil) }
    end

    def finalize
      LibCrypto.evp_pkey_free(@handle)
    end
  end

  class Certificate
    getter handle : LibCrypto::X509

    def initialize(@handle)
    end

    def self.load(path : String) : Certificate
      new(PKI.read_pem(path) { |bio| LibCrypto.pem_read_bio_x509(bio, nil, nil, nil) })
    end

    def common_name : String?
      PKI.common_name(LibCrypto.x509_get_subject_name(@handle))
    end

    def matches_key?(key : Key) : Bool
      LibCrypto.x509_check_private_key(@handle, key.handle) == 1
    end

    def to_pem : String
      PKI.write_pem { |bio| LibCrypto.pem_write_bio_x509(bio, @handle) }
    end

    def to_text : String
      PKI.write_pem { |bio| LibCrypto.x509_print_ex(bio, @handle, 0, 0) }
    end

    def finalize
      LibCrypto.x509_free(@handle)
    end
  end

  class Request
    getter handle : Void*

    def initialize(@handle)
    end

    def self.load(path : String) : Request
      new(PKI.read_pem(path) { |bio| LibCrypto.pem_read_bio_x509_req(bio, nil, nil, nil) })
    end

    def common_name : String?
      PKI.common_name(LibCrypto.x509_req_get_subject_name(@handle))
    end

    def to_pem : String
      PKI.write_pem { |bio| LibCrypto.pem_write_bio_x509_req(bio, @handle) }
    end

    def finalize
      LibCrypto.x509_req_free(@handle)
    end
  end

  # --- High-level operations ----------------------------------------------

  def self.create_ca(name : String, days : Int32) : {Key, Certificate}
    key = Key.generate
    cert = build_cert(name, key.handle, days) do |x509|
      add_ext(x509, x509, x509, "basicConstraints", "critical,CA:TRUE,pathlen:0")
      add_ext(x509, x509, x509, "keyUsage", "critical,keyCertSign,cRLSign")
      add_ext(x509, x509, x509, "subjectKeyIdentifier", "hash")
    end
    LibCrypto.x509_set_issuer_name(cert, LibCrypto.x509_get_subject_name(cert))
    sign(cert, key)
    {key, Certificate.new(cert)}
  end

  def self.create_request(name : String, key : Key) : Request
    req = LibCrypto.x509_req_new
    raise OpenSSL::Error.new("X509_REQ_new") if req.null?
    request = Request.new(req)
    with_name(name) { |n| check LibCrypto.x509_req_set_subject_name(req, n), "X509_REQ_set_subject_name" }
    check LibCrypto.x509_req_set_pubkey(req, key.handle), "X509_REQ_set_pubkey"
    check_pos LibCrypto.x509_req_sign(req, key.handle, nil), "X509_REQ_sign"
    request
  end

  # Sign a node certificate for `name` over `pubkey` (an EVP_PKEY handle).
  def self.issue(ca_key : Key, ca_cert : Certificate, name : String, pubkey : Void*,
                 sans : Array(String), days : Int32) : Certificate
    cert = build_cert(name, pubkey, days) do |x509|
      issuer = ca_cert.handle
      add_ext(x509, issuer, x509, "basicConstraints", "critical,CA:FALSE")
      add_ext(x509, issuer, x509, "keyUsage", "critical,digitalSignature")
      add_ext(x509, issuer, x509, "extendedKeyUsage", "serverAuth,clientAuth")
      add_ext(x509, issuer, x509, "subjectAltName", sans.join(","))
      add_ext(x509, issuer, x509, "subjectKeyIdentifier", "hash")
      add_ext(x509, issuer, x509, "authorityKeyIdentifier", "keyid:always")
    end
    LibCrypto.x509_set_issuer_name(cert, LibCrypto.x509_get_subject_name(ca_cert.handle))
    sign(cert, ca_key)
    Certificate.new(cert)
  end

  # Public key of a CSR, after checking the CSR is signed by that key.
  def self.request_pubkey(req : Request) : Void*
    pkey = LibCrypto.x509_req_get_pubkey(req.handle)
    raise Error.new("CSR has no public key") if pkey.null?
    unless LibCrypto.x509_req_verify(req.handle, pkey) == 1
      LibCrypto.evp_pkey_free(pkey)
      raise Error.new("CSR signature is invalid")
    end
    pkey
  end

  # SAN entries for a node: its own name first, then any extra DNS names/IPs.
  def self.subject_alt_names(name : String, dns : Array(String), ips : Array(String)) : Array(String)
    sans = [] of String
    sans << (ip?(name) ? "IP:#{name}" : "DNS:#{name}")
    dns.each { |d| sans << "DNS:#{d}" }
    ips.each do |ip|
      raise Error.new("Not a valid IP address: #{ip}") unless ip?(ip)
      sans << "IP:#{ip}"
    end
    sans.uniq
  end

  def self.ip?(s : String) : Bool
    Socket::IPAddress.valid?(s)
  end

  def self.valid_name?(name : String) : Bool
    /\A[A-Za-z0-9][A-Za-z0-9._:-]*\z/.matches?(name)
  end

  # --- Low-level helpers --------------------------------------------------

  private def self.build_cert(name : String, pubkey : Void*, days : Int32, &) : LibCrypto::X509
    x509 = LibCrypto.x509_new
    raise OpenSSL::Error.new("X509_new") if x509.null?
    check LibCrypto.x509_set_version(x509, 2), "X509_set_version" # v3
    set_random_serial(x509)
    # Backdate a little to tolerate clock skew between nodes.
    LibCrypto.x509_gmtime_adj(LibCrypto.x509_getm_not_before(x509), -300)
    LibCrypto.x509_gmtime_adj(LibCrypto.x509_getm_not_after(x509), days.to_i64 * 86_400)
    with_name(name) { |n| check LibCrypto.x509_set_subject_name(x509, n), "X509_set_subject_name" }
    check LibCrypto.x509_set_pubkey(x509, pubkey), "X509_set_pubkey"
    yield x509
    x509
  rescue ex
    LibCrypto.x509_free(x509) if x509
    raise ex
  end

  private def self.set_random_serial(x509 : LibCrypto::X509) : Nil
    bn = LibCrypto.bn_new
    begin
      check LibCrypto.bn_rand(bn, 127, 0, 0), "BN_rand"
      serial = LibCrypto.bn_to_asn1_integer(bn, LibCrypto.x509_get_serial_number(x509))
      raise OpenSSL::Error.new("BN_to_ASN1_INTEGER") if serial.null?
    ensure
      LibCrypto.bn_free(bn)
    end
  end

  private def self.add_ext(x509 : LibCrypto::X509, issuer : LibCrypto::X509, subject : LibCrypto::X509, name : String, value : String) : Nil
    # X509V3_CTX is a small public struct; a zeroed oversized buffer stands in
    # for it (X509V3_set_ctx fills the fields, a zero db means "no config").
    ctx = Bytes.new(256)
    LibCrypto.x509v3_set_ctx(ctx.to_unsafe.as(Void*), issuer, subject, nil, nil, 0)
    nid = LibCrypto.obj_sn2nid(name)
    ext = LibCrypto.x509v3_ext_nconf_nid(nil, ctx.to_unsafe.as(Void*), nid, value)
    raise OpenSSL::Error.new("Invalid #{name} extension '#{value}'") if ext.null?
    begin
      # stdlib binds X509_add_ext's int result as a pointer; 0 means failure.
      raise OpenSSL::Error.new("X509_add_ext") if LibCrypto.x509_add_ext(x509, ext, -1).null?
    ensure
      LibCrypto.x509_extension_free(ext)
    end
  end

  private def self.sign(x509 : LibCrypto::X509, key : Key) : Nil
    # Ed25519 signs the message directly, so no digest is passed.
    check_pos LibCrypto.x509_sign(x509, key.handle, nil), "X509_sign"
  end

  private def self.with_name(cn : String, &) : Nil
    name = LibCrypto.x509_name_new
    begin
      # stdlib binds this function's int result as a pointer; 0 means failure.
      if LibCrypto.x509_name_add_entry_by_txt(name, "CN", LibCrypto::ROCO_MBSTRING_ASC, cn, cn.bytesize, -1, 0).null?
        raise OpenSSL::Error.new("X509_NAME_add_entry_by_txt")
      end
      yield name
    ensure
      LibCrypto.x509_name_free(name)
    end
  end

  protected def self.common_name(name : LibCrypto::X509_NAME) : String?
    buf = Bytes.new(256)
    len = LibCrypto.x509_name_get_text_by_nid(name, LibCrypto::ROCO_NID_COMMON_NAME, buf, buf.size)
    len > 0 ? String.new(buf[0, len]) : nil
  end

  protected def self.read_pem(path : String, &)
    raise Error.new("File not found: #{path}") unless File.exists?(path)
    data = File.read(path)
    bio = LibCrypto.bio_new_mem_buf(data.to_unsafe, data.bytesize)
    begin
      obj = yield bio
      raise Error.new("Could not parse #{path} (not a valid PEM file of the expected type)") if obj.null?
      obj
    ensure
      LibCrypto.BIO_free(bio)
    end
  end

  protected def self.write_pem(&) : String
    bio = LibCrypto.BIO_new(LibCrypto.bio_s_mem)
    begin
      check_pos (yield bio), "PEM write"
      buf = Bytes.new(LibCrypto.bio_ctrl_pending(bio))
      String.new(buf[0, LibCrypto.bio_read(bio, buf, buf.size)])
    ensure
      LibCrypto.BIO_free(bio)
    end
  end

  private def self.check(ret : Int, what : String) : Nil
    raise OpenSSL::Error.new(what) unless ret == 1
  end

  private def self.check_pos(ret : Int, what : String) : Nil
    raise OpenSSL::Error.new(what) unless ret > 0
  end
end
