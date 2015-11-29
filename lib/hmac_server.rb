require 'digest/sha1'
require 'sinatra'
require 'crypto_tools'


hmac_key=""
prng=Random.new(1234)
16.times{hmac_key+=prng.rand(255).chr.to_s} 

def str_cmp(a,b)
  if a.length != b.length
    return false
  end
  a.bytes.each_with_index do |char,i| 
    if char != b[i].bytes[0]
      return false
    end
    sleep(0.005)
  end
  return true
end
def hmac(key,message)
  key=key.clone
  if key.length > 64
    key = Digest::SHA1.digest(key)
  end
  if key.length < 64
    key << "\0"*(64-key.length)
  end
  o_key_pad = CryptoTools.xor_str(([0x5c]*64).pack("C*"),key).force_encoding('ascii-8bit')
  i_key_pad = CryptoTools.xor_str(([0x36]*64).pack("C*"),key).force_encoding('ascii-8bit')
  return Digest::SHA1.hexdigest(o_key_pad+Digest::SHA1.digest(i_key_pad+message.force_encoding('ascii-8bit').force_encoding('ascii-8bit')))
end

get '/test' do
  file_name=params['file']
  signature=hmac(hmac_key,File.readlines(file_name).join)
  body_str=""
  # <p> hmac key: #{hmac_key.inspect}
  #  <p>file: #{params['file']} </p>
  #  <p>signature: #{params['signature']}</p>
  #  <p>true signature: #{signature}</p>

  # if str_cmp("Hello World","Hello World")
  #   body_str+="<br> Test strings match"
  # end
  if str_cmp([signature].pack("H*"),[params['signature']].pack("H*"))
    File.readlines(file_name).each do |l| 
      body_str+=("<br>"+l.chomp)
    end
  else
    body_str="<br> Signature mismatch, file untrusted!"
    status 500
  end
  return body_str
end
