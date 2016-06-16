
require 'openssl'
require 'pubkey'
require 'securerandom'
class SRPServer
  def initialize()
    @k=3
    @dh_key = DiffieHellman.new(NIST_PRIME,2)
    @client = nil
    @v = nil
    @salt=nil
    @pubA = nil
  end
  def register(client,email,password)
    @client = client
    client.connect(self)
    @salt = SecureRandom.random_number(2**256)
    x = Digest::SHA2.digest("#{@salt}#{password}").unpack("H*")[0].to_i(16)
    g = @dh_key.G
    p = @dh_key.P
    @v=g.modexp(x,p)
    x=0
  end
  def connect(client)
    @client = client
  end
  def login(email,pub_key)
    @pubA = pub_key
    @client.verify(@salt,@k*@v + @dh_key.pub_key)
  end
  def verify(key)
    u = Digest::SHA2.digest("#{@pubA}#{@k*@v+@dh_key.pub_key}").unpack("H*")[0].to_i(16)
    s = (@pubA*@v.modexp(u,@dh_key.P)).modexp(@dh_key.a,@dh_key.P)
    k = Digest::SHA2.digest("#{s}")
    hmac_key = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),k,[@salt.to_s(16)].pack("H*"))
    return hmac_key==key
  end
end
class SRPClient
  def initialize(email,password)
    @email=email
    @password= password
    @k=3
    @dh_key = DiffieHellman.new(NIST_PRIME,2)
    @server = nil
  end
  def connect(server)
    @server = server
  end
  def login()
    @server.login(@email,@dh_key.pub_key)
  end
  def verify(salt,pubB)
    u = Digest::SHA2.digest("#{@dh_key.pub_key}#{pubB}").unpack("H*")[0].to_i(16)
    x = Digest::SHA2.digest("#{salt}#{@password}").unpack("H*")[0].to_i(16)
    a=@dh_key.a
    n=@dh_key.P
    g=@dh_key.G
    s = (pubB - @k*g.modexp(x,n) ).modexp(a+u*x,n)
    k = Digest::SHA2.digest("#{s}")
    hmac_key = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),k,[salt.to_s(16)].pack("H*"))
    if @server.verify(hmac_key)
      puts "Logged in!"
    else
      raise "Secure Remote Password authetication failed"
    end
  end
end
