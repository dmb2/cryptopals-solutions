require 'converters'
require 'openssl'
require 'block_crypto'

class MersenneTwisterRng
  @@MT = [0]*624
  @@index = 0 
  def self.init(seed)
    @@MT[0] = seed
    1.upto(624) do |i| 
      @@MT[i]= Fixnum(1812433253*(@@MT[i-1] ^ @@MT[i-1]>>30)+i)
    end
  end
  def self.rand()
    if @@index == 0
      generate_numbers
    end
    y = @@MT[@@index]
    y = y ^ y >> 11
    y = y ^ y << 7 & 2636928640
    y = y ^ y << 15 & 4022730752
    y = y ^ y >> 18
    index=(index+1)%624
    return Fixnum(y)
  end
  def self.generate_numbers
    624.times do |i| 
      y = Fixnum((@@MT[i]&0x80000000)+@@MT[(i+1)%624]&0x7fffffff)
      @@MT[i]=@@MT[(i+397)%624]^y >> 1
      if not y%2
        @@MT[i]=@@MT[i]^0x9908b0df
      end
    end
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
end
