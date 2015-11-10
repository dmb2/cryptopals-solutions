require 'crypto_tools'
require 'block_crypto'
require 'stream_cipher'
require 'openssl'
require 'base64'
require 'hash_functions'
class MACServer 
  @@key = File.readlines("/usr/share/dict/words").sample.strip
  def sign_message(message)
    # puts "key: #{@@key}, #{@@key.length}"
    Hash.sha1((@@key+message).force_encoding("ascii-8bit"))
  end
  def verify_message(message,mac)
    return Hash.sha1((@@key+message).force_encoding("ascii-8bit"))==mac
  end
end
class MD4MACServer 
  @@key = File.readlines("/usr/share/dict/words").sample.strip
  def sign_message(message)
    Hash.md4((@@key+message).force_encoding("ascii-8bit"))
  end
  def verify_message(message,mac)
    return Hash.md4((@@key+message).force_encoding("ascii-8bit"))==mac
  end
end


class CTROracleServer
  @@ctr_key = CryptoTools.random_byte_string(16)
  @@nonce="\0"*8
  def encrypt(plain_text)
    return StreamCrypto.aes_ctr_encrypt(plain_text,@@nonce,@@ctr_key)
  end
  def edit(cipher_text,offset,newtext)
    keystream = StreamCrypto.aes_ctr_keystream(cipher_text.length,@@nonce,@@ctr_key)
    # we can do this two ways:
    # 1. decrypt cipher_text, splice in newtext and re-encrypt
    # 2. encrypt newtext with the keystream for that portion of the
    #    cipher text and splice the resulting cipher text into the old
    #    encrypted text
    # This implements 2.
    new_cipher_text=CryptoTools.xor_str(keystream.slice(offset,newtext.length),newtext)
    cipher_text.slice!(offset,newtext.length)
    return cipher_text.insert(offset,new_cipher_text)
  end
end

class CBCPaddingServer
  @@sessions=["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
              "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
              "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
              "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
              "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
              "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
              "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
              "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
              "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
              "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" ]
  @@aes_key = CryptoTools.random_byte_string(16)
  def get_session_cookie
    iv=CryptoTools.random_byte_string(16)
    plain_text=Base64.decode64(@@sessions[Random.rand(@@sessions.length)])
    return iv,BlockCrypto.aes_cbc_encrypt(plain_text,@@aes_key,iv)
  end
  def valid_decrypt(session_cookie,iv)
    begin
      plain_text=BlockCrypto.aes_cbc_decrypt(session_cookie,@@aes_key,iv)
    rescue EncodingError
      # puts "Caught EncodingError"
      return false
    end
    return true
  end
end

class Server
  @@aes_key = CryptoTools.random_byte_string(16)
  def issue_cookie(userdata)
    raw_cookie_str="comment1=cooking%20MCs;userdata="
    raw_cookie_str+=sanitize(userdata)
    raw_cookie_str+=";comment2=%20like%20a%20pound%20of%20bacon"
    return Converters.str_to_hex(raw_cookie_str)
  end
  def decode_cookie(cookie)
    return Converters.hex_to_bytes(cookie)
  end
  def parse_cookie(cookie)
    session = Hash.new("")
    decode_cookie(cookie).split(";").each do |pair| 
      key,value=pair.split("=")
      session[key]=value
    end
    return session
  end
  def sanitize(string)
    sani_str=string.gsub(/;/,"%3B")
    sani_str=sani_str.gsub(/=/,"%3D")
    return sani_str
  end
  def admin?(cookie)
    session = parse_cookie(cookie)
    return session["admin"]=="true"
  end
end

class CBCServer < Server
  def issue_cookie(userdata)
    raw_cookie_str="comment1=cooking%20MCs;userdata="
    raw_cookie_str+=sanitize(userdata)
    raw_cookie_str+=";comment2=%20like%20a%20pound%20of%20bacon"
    return Converters.str_to_hex(BlockCrypto.aes_cbc_encrypt(raw_cookie_str,
                                                             @@aes_key,
                                                             "\x0"*16))
  end
  def decode_cookie(cookie)
    return BlockCrypto.aes_cbc_decrypt(Converters.hex_to_bytes(cookie),
                                       @@aes_key, "\x0"*16)
  end
end
class CBCIVServer < Server
  def issue_cookie(userdata)
    raw_cookie_str="comment1=cooking%20MCs;userdata="
    raw_cookie_str+=sanitize(userdata)
    raw_cookie_str+=";comment2=%20like%20a%20pound%20of%20bacon"
    return Converters.str_to_hex(BlockCrypto.aes_cbc_encrypt(raw_cookie_str,
                                                             @@aes_key,
                                                             @@aes_key))
  end
  def key()
    return @@aes_key
  end
  def valid_ascii(string)
    bytes = string.bytes()
    bytes.each do |byte| 
      if byte < 32 or byte > 126
        return false
      end
    end
    return true
  end
  def decode_cookie(cookie)
    clear_cookie=BlockCrypto.aes_cbc_decrypt(Converters.hex_to_bytes(cookie),
                                             @@aes_key, @@aes_key)
    if not valid_ascii(clear_cookie)
      raise "Error Decrypting Cookie: #{clear_cookie}"
    end
    return clear_cookie
  end
end

class CTRServer < Server
  @@nonce = "\0"*8
  def issue_cookie(userdata)
    raw_cookie_str="comment1=cooking%20MCs;userdata="
    raw_cookie_str+=sanitize(userdata)
    raw_cookie_str+=";comment2=%20like%20a%20pound%20of%20bacon"
    return Converters.str_to_hex(StreamCrypto.aes_ctr_encrypt(raw_cookie_str,
                                                             @@nonce,
                                                             @@aes_key))
  end
  def decode_cookie(cookie)
    return StreamCrypto.aes_ctr_decrypt(Converters.hex_to_bytes(cookie),
                                       @@nonce , @@aes_key)
  end
end
class ECBServer
  @@aes_key = CryptoTools.random_byte_string(16)
  def parse_cookie(cookie_str)
    session = Hash.new("")
    cookie_str.split("&").each do |pair| 
      key,value=pair.split("=")
      session[key]=value
    end
    return session
  end
  def encode_raw_cookie(session)
    cookie=""
    session.each do |key,value| 
      cookie+=sprintf("%s=%s&",key,value)
    end
    return cookie.slice(0,cookie.length-1)
  end
  def sanitize(string)
    return string.scan(/[^&=]/).join
  end
  def profile_for(email)
    session = Hash.new("")
    session["email"]=sanitize(email)
    session["uid"]=10
    session["role"]="user"
    return encode_raw_cookie(session)
  end
  def issue_cookie(email_addr)
    return Converters.str_to_hex(BlockCrypto.AES_128_ECB(profile_for(email_addr),@@aes_key))
  end
  def decode_cookie(hex_encoded_cookie)
    ecb_decipher = OpenSSL::Cipher.new 'AES-128-ECB'
    ecb_decipher.decrypt
    ecb_decipher.key=@@aes_key
    raw_cookie = ecb_decipher.update(Converters.hex_to_bytes(hex_encoded_cookie))+ecb_decipher.final
    return parse_cookie(raw_cookie)
  end
  def admin?(cookie)
    session = decode_cookie(cookie)
    return session["role"]=="admin"
  end
end
