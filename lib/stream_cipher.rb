require 'converters'
require 'openssl'
require 'block_crypto'

class StreamCrypto
  def self.aes_ctr_encrypt(clear_text,nonce,key)
    if nonce.is_a?(String)==false
      raise RuntimeError "Nonce is not a string, please use a byte string to initialize the nonce"
    end
    puts "Hello Dave"
  end
  def self.aes_ctr_decrypt(cipher_text,nonce,key)
    if nonce.is_a?(String)==false
      raise RuntimeError "Nonce is not a string, please use a byte string to initialize the nonce"
    end
    
  end
end
