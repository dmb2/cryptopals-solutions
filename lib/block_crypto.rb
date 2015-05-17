require 'converters'
require 'openssl'

class String
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
    cipher_text = cipher.update(clear_text) + cipher.final
    # cbc magic
    blocks=[]
    block_size=iv.length
    
    return cipher_text
  end
  def self.aes_cbc_decrypt(cipher_text,key,iv)
    decipher = OpenSSL::Cipher.new 'AES-128-ECB'
    decipher.decrypt
    decipher.key=key
    # cbc magic
    return decipher.update(cipher_text)+decipher.final
  end
end
