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
  def self.Hello
    puts "Block Crypto Hello!"
  end
end
