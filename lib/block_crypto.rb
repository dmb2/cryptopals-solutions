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
    # cbc magic
    blocks=[]
    block_size=iv.length
    # Refactor this to use one loop instead of two
    (Float(clear_text.length)/block_size).ceil().times do |i| 
      blocks+=[clear_text.slice(block_size*i,block_size)]
    end
    blocks[-1]=blocks[-1].pkcs7pad(block_size)
    firstblock=Converters.hex_to_bytes(CryptoTools.hex_xor(Converters.str_to_hex(blocks.slice!(0)),
                                                         Converters.str_to_hex(iv)))
    blocks+=[firstblock];
    blocks.each.with_index do |block,i| 
      hex_block=Converters.str_to_hex(block)
      prev_hex_block=Converters.str_to_hex(blocks[i-1])
      printf "%s\n",hex_block
      scrambled=CryptoTools.hex_xor(hex_block,prev_hex_block)
      blocks[i]=cipher.update(Converters.hex_to_bytes(scrambled))
    end
    blocks=[firstblock]+blocks
    return blocks.join+cipher.final
  end
  def self.aes_cbc_decrypt(cipher_text,key,iv)
    decipher = OpenSSL::Cipher.new 'AES-128-ECB'
    decipher.decrypt
    decipher.key=key
    # cbc magic
    blocks=[]
    block_size=iv.length
    # Refactor this to use one loop instead of two
    (Float(cipher_text.length)/block_size).ceil().times do |i| 
      blocks+=[cipher_text.slice(block_size*i,block_size)]
    end
    decipher.update(blocks.slice!(0))
    blocks.each.with_index do |block,i| 
      prev=""
      if i==0
        prev=Converters.str_to_hex(iv)
      else
        prev=Converters.str_to_hex(blocks[i-1])
      end
      hex_block = Converters.str_to_hex(decipher.update(block))
      clear_hex=CryptoTools.hex_xor(hex_block,prev)
      printf "%s\n",clear_hex
      blocks[i]=Converters.hex_to_bytes(clear_hex)
    end
    # decipher.final may be added to each block.. 
    return blocks.join+decipher.final
    # return decipher.update(cipher_text)+decipher.final
  end
end
