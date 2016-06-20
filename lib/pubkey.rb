require 'digest/sha2'
require 'integer_utils'
require 'securerandom'
require 'openssl'

class DiffieHellman
  attr_reader :P
  attr_reader :G
  attr_reader :a
  def initialize(p,g)
    @P = p
    @G = g
    @a = SecureRandom.random_number(2**256)%p
  end
  def pub_key()
    @G.modexp(@a,@P)
  end
  def session(public_key)
    public_key.modexp(@a,@P)
  end
  def sha2_session(public_key)
    Digest::SHA2.digest([self.session(public_key)].pack("C*"))
  end
  def sha1_session(public_key)
    Digest::SHA1.digest([self.session(public_key)].pack("C*"))
  end
  def to_s()
    "p: #{@P} \n g: #{@G} \n x: #{@a}"
  end
end

class RSAPub
  attr_reader :e
  attr_reader :n
  def initialize(e,n)
    @e=e
    @n=n
  end
end
class RSAPriv
  attr_reader :d
  attr_reader :n
  def initialize(d,n)
    @d=d
    @n=n
  end
end
class RSA
  def self.encrypt(message,pub_key)
    m = message.unpack("H*")[0].to_i(16)
    c = m.modexp(pub_key.e,pub_key.n)
    return c.to_s(16)
  end
  def self.decrypt(ciphertext,key)
   c = ciphertext.to_i(16)
   m = c.modexp(key.d,key.n)
   return [m.to_s(16)].pack("H*")
  end
  def self.gen_pair(e)
    p = OpenSSL::BN::generate_prime(512).to_i 
    q = OpenSSL::BN::generate_prime(512).to_i
    n = p*q
    et = (p-1)*(q-1)
    d = e.invmod(et)
    return [RSAPub.new(e,n),RSAPriv.new(d,n)] 
  end
end
