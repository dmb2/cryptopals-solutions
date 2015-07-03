require 'crypto_tools'
require 'block_crypto'
require 'openssl'
require 'base64'

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
  @@aes_key = BlockCrypto.random_byte_string(16)
  # @@iv = BlockCrypto.random_byte_string(16)
  def get_session_cookie
    iv=BlockCrypto.random_byte_string(16)
    plain_text=Base64.decode64(@@sessions[Random.rand(@@sessions.length)])
    # plain_text="Alice was beginning to get very tired of sitting by her sister on the"
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
class CBCServer
  @@aes_key = BlockCrypto.random_byte_string(16)
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

class ECBServer
  @@aes_key = BlockCrypto.random_byte_string(16)
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
