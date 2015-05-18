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
    # cipher_text = cipher.update(clear_text) + cipher.final
    # cbc magic
    blocks=[]
    block_size=iv.length
    (Float(clear_text.length)/block_size).ceil().times do |i| 
      blocks+=[Converters.str_to_hex(clear_text.slice(block_size*i,block_size))]
    end
    blocks[-1].pkcs7pad(block_size)
    blocks.each.with_index do |block,i| 
      prev=""
      if i==0
        prev=Converters.str_to_hex(iv)
      else
        prev=Converters.str_to_hex(blocks[i-1])
      end
      scrambled=CryptoTools.hex_xor(block,prev)
      blocks[i]=Converters.hex_to_bytes(cipher.update(
                                         Converters.hex_to_bytes(scrambled)))
    end
    return blocks.join
  end
  def self.aes_cbc_decrypt(cipher_text,key,iv)
    decipher = OpenSSL::Cipher.new 'AES-128-ECB'
    decipher.decrypt
    decipher.key=key
    # cbc magic
    return decipher.update(cipher_text)+decipher.final
  end
end
