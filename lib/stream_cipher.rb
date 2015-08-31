require 'converters'
require 'openssl'
require 'block_crypto'

class MersenneTwisterRng
  def initialize(seed)
    @N = 624
    @M = 397
    @A = 0x9908b0df
    @idx = @N
    @mt = [0]*@N
    if seed.is_a?(Array) and seed.length == @N
      @mt = seed
    elsif seed.is_a?(Fixnum)
      @mt[0] = seed
      1.upto(@N) do |i| 
        @mt[i] = self.int32(1812433253*(@mt[i-1]^(@mt[i-1]>>30))+i)
      end
    else
      raise "Seed is wrong type: #{seed.class}"
    end
  end
  def int32(x)
    return (0xffffffff & x)
  end
  def extract_number
    if @idx >= @N
      twist
    end
    result = temper(@mt[@idx])
    @idx+=1
    return result
  end
  def diffuse(y,c,b,dir=:left)
    if dir!=:left and dir!=:right
      raise sprintf("Invalid direction: %s",dir.inspect)
    end
    return y ^ ((dir==:left ? y << c : y >> c) & b)
  end
  def temper(y)
    y = self.diffuse(y,11,0xffffffff,:right)
    y = self.diffuse(y,7,0x9d2c5680,:left)
    y = self.diffuse(y,15,0xefc60000,:left)
    return self.diffuse(y,18,0xffffffff,:right)
  end
  def twist
    @N.times do |i| 
      y = self.int32((@mt[i] & 0x80000000) +
                (@mt[(i+1)%@N] & 0x7fffffff))
      @mt[i] = @mt[(i+@M)%@N] ^ y >> 1
      if y%2 != 0
        @mt[i]^=@A
      end
    end
    @idx=0
  end
end

class StreamCrypto
  def self.aes_ctr_encrypt(clear_text,nonce,key)
    counter=nonce.unpack('q')[0]
    keystream = ""
    cipher = OpenSSL::Cipher.new 'AES-128-ECB'
    cipher.padding=0
    cipher.encrypt
    cipher.key=key
    (Float(clear_text.length)/key.length).ceil().times do |i| 
      stream_nonce="\0"*8+[counter].pack('q')
      keystream += cipher.update(stream_nonce)
      counter+=1
    end
    return CryptoTools.xor_str(keystream.slice(0,clear_text.length),clear_text)
  end
  def self.aes_ctr_decrypt(cipher_text,nonce,key)
    aes_ctr_encrypt(cipher_text,nonce,key)
  end
  def self.mtrng_encrypt(clear_text,key)
    if key > 0xFFFF
      raise "Key must be less than 16 bits"
    end
    mtrng=MersenneTwisterRng.new(key)
    # build the keystream
    keystream=[]
    clear_text.length.times do 
      keystream+=[mtrng.extract_number%256]
    end
    return CryptoTools.xor_str(keystream.pack("C*"),clear_text)
  end
  def self.mtrng_decrypt(cipher_text,key)
    mtrng_encrypt(cipher_text,key)
  end
end
