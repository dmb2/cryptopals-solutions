require 'converters'
require 'openssl'

class String
  def pkcs7strip
    str=self.clone
    # look at the last byte to determine padding amount
    nbytes=str.bytes[-1]
    # look at length-nbytes and make sure that it is also nbytes
    # slice off nbytes and verify that each on is nbytes
    if str.bytes[-nbytes] != nbytes
      raise EncodingError,"Invalid PKCS7 Padding"
    end
    pad_block=str.slice!(-nbytes,nbytes)
    pad_block.bytes.map do |byte| 
      if byte != nbytes
        raise EncodingError,"Invalid PKCS7 Padding"
      end
    end
    return str
  end
  def pkcs7pad(block_size)
    if block_size > 256
      raise EncodingError,"PKCS7 is not defined for block sizes larger than 256!"
    end
    nbytes = block_size - self.length
    if nbytes < 0
      raise EncodingError,"Trying to pad a string longer than the block size!"
    end
    nbytes = nbytes == 0 ? block_size : nbytes
    str=""
    nbytes.times{
      str+=nbytes.chr
    }
    return self+str
  end
  def blocks(block_size)
    blocks=[]
    (Float(self.length)/block_size).ceil().times do |i| 
      blocks.push(self.slice(i*block_size,block_size))
    end
    return blocks
  end
end

class BlockCrypto
  def self.aes_cbc_encrypt(clear_text,key,iv)
    cipher = OpenSSL::Cipher.new 'AES-128-ECB'
    cipher.padding = 0
    cipher.encrypt
    cipher.key=key
    # cbc magic
    block_size=iv.length
    blocks=clear_text.blocks(block_size)
    blocks[-1]=blocks[-1].pkcs7pad(block_size)
    if blocks[-1].length !=block_size
      pad_blocks=blocks.slice!(-1,1)[0].blocks(block_size)
      blocks+=pad_blocks
    end
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
  def self.break_aes_ecb(unknown_string,variable_length=false)
    # variable_length determines if the string changes length on
    # repeated calls to the oracle
    # 1. Determine block size and secret length
    secret_key=BlockCrypto.random_byte_string(16)
    prefix=''
    if variable_length==true
      prefix=BlockCrypto.random_byte_string(Random.rand(16))
    end
    init_len=BlockCrypto.AES_128_ECB(prefix+unknown_string,secret_key).length
    block_size=0
    secret_len=0
    17.times do |i| 
      len=BlockCrypto.AES_128_ECB(prefix+"A"*i+unknown_string,secret_key).length
      if len > init_len
        secret_len=init_len-i
        block_size=len-init_len
        break
      end
    end
    # 2. Detect ECB
    l=CryptoTools.detect_aes_ecb(BlockCrypto.AES_128_ECB(prefix+"A"*256+unknown_string,secret_key))
    if l==""
      raise "Did not detect ECB"
    end
    # 3. Make input block that is 1 byte short
    # 4. Create a list of ciphertexts from all possible last bytes
    # 5. Match the output of the 1 byte short to the list created in 4
    # for each byte
    #    3. make input block
    #    4. build dictionary of byte combinations
    #    5. check for byte in dictionary
    #    5a. add byte to decoded string
    decoded_str=""
    input_len=(init_len-1)
    # if a random number of bytes has been prepended, we have to strip
    # one off each time we don't detect a byte in the oracle, if not
    # we just take one
    pad_char="\x00"
    n_bytes=0
    secret_len.times do 
      input_len=(init_len-decoded_str.length-1)
      input_block=pad_char*input_len+decoded_str
      # puts input_block.inspect
      block_dictionary=Hash.new("")
      0.upto(255) do |c| 
        block_dictionary[BlockCrypto.AES_128_ECB(input_block.slice(-block_size+1,block_size-1)+c.chr,secret_key).slice(0,block_size)]=c.chr.to_s
      end
      cipher_text=BlockCrypto.AES_128_ECB(prefix+pad_char*input_len+unknown_string,secret_key)
      detected_byte=block_dictionary[cipher_text.slice(((init_len/block_size)-1)*block_size,block_size)]
      if detected_byte != ""
        decoded_str+=detected_byte
      end
      if detected_byte == pad_char
        n_bytes+=1
      end
    end
    return decoded_str.slice(n_bytes,decoded_str.length)
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
