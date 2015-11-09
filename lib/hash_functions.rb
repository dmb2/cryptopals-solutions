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
    mask = 0xffffffff
    #not my original idea, but this is quite elegant
    # taken from: http://rosettacode.org/wiki/SHA-1#Ruby
    f = [
      proc {|b, c, d| (b & c) | (b.^(mask) & d)},
      proc {|b, c, d| b ^ c ^ d},
      proc {|b, c, d| (b & c) | (b & d) | (c & d)},
      proc {|b, c, d| b ^ c ^ d},
    ].freeze
    k = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6].freeze

    words=chunk.unpack("N16")
    16.upto(79) do |i| 
      words[i] = rotl32((words[i-3]^words[i-8]^words[i-14]^words[i-16]),1)
    end
      t = 0
      4.times do |i|
        20.times do
          temp = (rotl32(a, 5) + f[i][b, c, d] + e + words[t] + k[i]) & mask
          a, b, c, d, e = temp, a, rotl32(b, 30), c, d
          t += 1
        end
      end
    return [a&mask,b&mask,c&mask,d&mask,e&mask]
  end
  def self.fixed_sha1(message,h)
    # very inefficient, but we won't be using this in any serious
    # application, MDpad creates a local copy of the message
    message.blocks(64).each do |chunk| 
      puts chunk.inspect
      a,b,c,d,e=self.compress_chunk(chunk,h[0],h[1],h[2],h[3],h[4])
      [a,b,c,d,e].each_with_index  do |x,i| 
        h[i]=(h[i]+x)&0xffffffff
      end
    end
    result=""
    h.each do |num| 
      result+=[num].pack("N*")
    end
    return result
  end
  def self.sha1(string)
    return fixed_sha1(self.MDpad(string),
                      [0x67452301,
                       0xEFCDAB89,
                       0x98BADCFE,
                       0x10325476,
                       0xC3D2E1F0])
  end
  
end
