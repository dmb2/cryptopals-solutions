require 'digest/sha2'
require 'securerandom'

class Integer
  def modexp(exponent,modulus)
    if modulus == 1
      return 0
    end
    result = 1
    base = self % modulus
    while exponent > 0
      if exponent%2 == 1
        result = (result*base) % modulus
      end
      exponent = exponent >> 1
      base = (base*base) % modulus
    end
    result
  end
end
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
