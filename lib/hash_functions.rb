require 'string_utils'
class Hash
  # https://en.wikipedia.org/wiki/Circular_shift
  def self.rotl32(value,count)
    return ((value << count) | (value >> 32-count))&0xFFFFFFFF
  end
  def self.rotr32(value,count)
    return ((value >> count) | (value << 32-count))&0xFFFFFFFF
  end
  def self.MDpad(message)
    bit_len = message.size << 3
    message += "\x80".force_encoding('ascii-8bit')
    while (message.size % 64) != 56
      message += "\0"
    end
    message = message.force_encoding("ascii-8bit") + [bit_len >> 32, bit_len & 0xFFFFFFFF].pack("N2")
    if (message.size % 64)!=0
      raise "Padding failed"
    end
    return message
  end
  def self.compress_chunk(chunk,a,b,c,d,e)
    words=[]
    chunk.blocks(4).each do |word| 
      words+=word.unpack("N*")
    end
    words+=[0]*(79-words.length)
    16.upto(79) do |i| 
      words[i] = rotl32((words[i-3]^words[i-8]^words[i-14]^words[i-16]),1)
    end
    f = 0
    k = 0
    80.times do |i| 
      if i < 20
        f = ((b & c) | (~b & d))
        k = 0x5A827999
      elsif i >= 20 and i < 40
        f = (b^c^d)
        k = 0x6ED9EBA1
      elsif i >= 40 and i < 60
        f = (b&c)|(b&d)|(c&d)
        k = 0x8F1BBCDC
      else 
        f = b ^ c ^ d
        k = 0xCA62C1D6
      end
      tmp = rotl32(a,5)+f + e + k + words[i]&0xFFFFFFFF
      e = d
      d = c
      c = rotl32(b,30)
      b = a 
      a = tmp
    end
    return [a,b,c,d,e]
  end
  def self.fixed_sha1(message,a,b,c,d,e)
    # very inefficient, but we won't be using this in any serious
    # application, MDpad creates a local copy of the message
    internal_message=self.MDpad(message)
    h=[a,b,c,d,e]
    internal_message.blocks(64).each do |chunk| 
      a,b,c,d,e=self.compress_chunk(chunk,h[0],h[1],h[2],h[3],h[4])
      h[0]+=a&0xFFFFFFFF
      h[1]+=b&0xFFFFFFFF
      h[2]+=c&0xFFFFFFFF
      h[3]+=d&0xFFFFFFFF
      h[4]+=e&0xFFFFFFFF
    end
    result=""
    h.each do |num| 
      result+=[num].pack("N*")
    end
    return result
    
  end
  def self.sha1(message)
    return fixed_sha1(message,
                      0x67452301,
                      0xEFCDAB89,
                      0x98BADCFE,
                      0x10325476,
                      0xC3D2E1F0)
  end
  
end
