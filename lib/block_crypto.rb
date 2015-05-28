require 'converters'
require 'openssl'

class String
  def pkcs7strip
    str=self.clone
    nbytes=str[-1].bytes[0]
    nbytes.times{
      if str[-1].bytes[0]==nbytes
        str.slice!(-1)
      end
    }
    return str
  end
  def pkcs7pad(block_size)
    if block_size > 256
      raise "PKCS7 is not defined for block sizes larger than 256!"
    end
    nbytes = block_size - self.length
    if nbytes < 0
      raise "Trying to pad a string longer than the block size!"
    end
    str=""
    nbytes.times{
      str+=nbytes.chr
    }
    return self+str
  end
end

class BlockCrypto
  def self.aes_cbc_encrypt(clear_text,key,iv)
    cipher = OpenSSL::Cipher.new 'AES-128-ECB'
    cipher.encrypt
    cipher.key=key
    # cbc magic
    block_size=iv.length
    blocks=[]
    (Float(clear_text.length)/block_size).ceil().times do |i| 
      blocks.push(clear_text.slice(i*block_size,block_size))
    end
    blocks[-1]=blocks[-1].pkcs7pad(block_size)
    blocks.unshift(iv)
    ct = [iv]
    1.upto(blocks.length-1) do |i| 
      ct[i] = cipher.update(CryptoTools.xor_str(blocks[i],ct[i-1]))
    end
    return ct[1..-1].join
  end
  def self.random_byte_string(nbytes)
    return nbytes.times.map{ Random.rand(256) }.pack("C*")
  end
  def self.encryption_oracle(input)
    key=random_byte_string(16)
    ecb_cipher = OpenSSL::Cipher.new 'AES-128-ECB'
    ecb_cipher.encrypt
    ecb_cipher.key=key
    cbc_cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    cbc_cipher.encrypt
    cbc_cipher.key=key
    cbc_cipher.iv=random_byte_string(16)
    padded_input=random_byte_string(5+rand(5))+input+random_byte_string(5+rand(5))
    if rand(2)==0
      return cbc_cipher.update(padded_input)+cbc_cipher.final
    else
      return ecb_cipher.update(padded_input)+ecb_cipher.final
    end
  end
  def self.AES_128_ECB(input,key)
      ecb_cipher = OpenSSL::Cipher.new 'AES-128-ECB'
      ecb_cipher.encrypt
      ecb_cipher.key=key
      return ecb_cipher.update(input)+ecb_cipher.final
  end
  def self.aes_cbc_decrypt(cipher_text,key,iv)
    decipher = OpenSSL::Cipher.new 'AES-128-ECB'
    decipher.decrypt
    decipher.padding = 0
    decipher.key=key
    block_size=iv.length
    blocks=[]
    (Float(cipher_text.length)/block_size).ceil().times do |i| 
      blocks.push(cipher_text.slice(i*block_size,block_size))
    end
    decipher.update(blocks[0])
    blocks.unshift(iv)
    pt = []
    1.upto(blocks.length-1) do |i| 
      pt[i] = CryptoTools.xor_str(decipher.update(blocks[i]),blocks[i-1])
    end
    pt[-1]=pt[-1].pkcs7strip
    return pt.join
  end
end
