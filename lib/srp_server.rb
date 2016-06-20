
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

class SimpleSRPServer
  def initialize()
    @client = nil
    @salt = nil
    @v = nil
    @username = nil
    @dh_key = DiffieHellman.new(NIST_PRIME,2)
  end
  def register(client,username,password)
    @client = client
    @username = username
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
    @u = SecureRandom.random_number(2**128)
    @client.verify(@salt,@dh_key.pub_key,@u)
  end
  def verify(key)
    s = (@pubA*@v.modexp(@u,NIST_PRIME)).modexp(@dh_key.a,NIST_PRIME)
    k = Digest::SHA2.digest("#{s}")
    hmac_key = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),k,[@salt.to_s(16)].pack("H*"))
    return hmac_key==key
  end
end
class SimpleSRPClient
  def initialize(email,password)
    @email = email
    @password = password
    @dh_key = DiffieHellman.new(NIST_PRIME,2)
    @server = nil
  end
  def connect(server)
    @server = server
  end
  def login()
    @server.login(@email,@dh_key.pub_key)
  end
  def verify(salt,pubB,u)
    
    x = Digest::SHA2.digest("#{salt}#{@password}").unpack("H*")[0].to_i(16)
    a = @dh_key.a
    s = pubB.modexp(a + u*x,NIST_PRIME)
    k = Digest::SHA2.digest("#{s}")
    hmac_key = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),k,[salt.to_s(16)].pack("H*"))
    if @server.verify(hmac_key)
      puts "Logged in!"
    else
      raise "Secure Remote Password authetication failed"
    end
  end
end

class SimpleSRPMITM 
  attr_reader :cracked_pw
  def initialize
    @client = nil
    @pubA = nil
    @cracked_pw = nil
    @x_map = {}
    words = File.read("/usr/share/dict/words").split("\n").slice(0,500)
    words.each do |pw| 
      @x_map[pw] = Digest::SHA2.digest("0#{pw}").unpack("H*")[0].to_i(16)
    end
  end
  def connect(client)
    @client = client
  end
  def login(email,pubA)
    @pubA=pubA
    # send salt=0, B=2, u=1 this forces the client to compute
    # something we know, namely (pubA*g^x)%n, then if we can enumerate
    # all values of x, we can crack the password.
    @client.verify(0,2,1) 
  end
  def verify(hmac_key)
    @x_map.each do |pw,x|
      s = (@pubA*2.modexp(x,NIST_PRIME))%NIST_PRIME
      k = Digest::SHA2.digest("#{s}")
      key = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),k,[0.to_s(16)].pack("H*"))
      if key == hmac_key
        @cracked_pw = pw
        break
      end
    end
    return true
  end
end
