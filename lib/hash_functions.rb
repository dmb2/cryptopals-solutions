require 'string_utils'
class Hash
  # https://en.wikipedia.org/wiki/Circular_shift
  def self.rotl32(value,count)
    return ((value << count) | (value >> 32-count))&0xFFFFFFFF
  end
  def self.rotr32(value,count)
    return ((value >> count) | (value << 32-count))&0xFFFFFFFF
  end
  def self.MDpad(message,endian=:big)
    if not (endian==:big or endian==:little)
      raise "Must specify endianness as :big or :little"
    end
    bit_len = message.size << 3
    message += "\x80".force_encoding('ascii-8bit')
    while (message.size % 64) != 56
      message += "\0"
    end
 
    if endian==:big
      message = message.force_encoding("ascii-8bit") + [bit_len >> 32, bit_len & 0xFFFFFFFF].pack("N2")
    else
      message = message.force_encoding("ascii-8bit") + [ bit_len & 0xFFFFFFFF,bit_len >> 32].pack("V2")
    end
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
  def self.compress_md4chunk(chunk,a,b,c,d)
    #stolen from http://rosettacode.org/wiki/MD4#Ruby
    mask=0xffffffff
    f = proc {|x, y, z| x & y | x.^(mask) & z}
    g = proc {|x, y, z| x & y | x & z | y & z}
    h = proc {|x, y, z| x ^ y ^ z}
    r = proc {|v, s| (v << s).&(mask) | (v.&(mask) >> (32 - s))}

    x=chunk.unpack("V16")
    aa, bb, cc, dd = a, b, c, d
    [0, 4, 8, 12].each {|i|
      a = r[a + f[b, c, d] + x[i] , 3]; i += 1
      d = r[d + f[a, b, c] + x[i],  7]; i += 1
      c = r[c + f[d, a, b] + x[i], 11]; i += 1
      b = r[b + f[c, d, a] + x[i], 19]
    }
    [0, 1, 2, 3].each {|i|
      a = r[a + g[b, c, d] + x[i] + 0x5a827999,  3]; i += 4
      d = r[d + g[a, b, c] + x[i] + 0x5a827999,  5]; i += 4
      c = r[c + g[d, a, b] + x[i] + 0x5a827999,  9]; i += 4
      b = r[b + g[c, d, a] + x[i] + 0x5a827999, 13]
    }
    [0, 2, 1, 3].each {|i|
      a = r[a + h[b, c, d] + x[i] + 0x6ed9eba1,  3]; i += 8
      d = r[d + h[a, b, c] + x[i] + 0x6ed9eba1,  9]; i -= 4
      c = r[c + h[d, a, b] + x[i] + 0x6ed9eba1, 11]; i += 8
      b = r[b + h[c, d, a] + x[i] + 0x6ed9eba1, 15]
    }
    return [(a+aa)&mask,(b+bb)&mask,(c+cc)&mask,(d+dd)&mask]
  end
  def self.fixed_md4(message,h)
    message.blocks(64).each do |chunk| 
      h = self.compress_md4chunk(chunk,h[0],h[1],h[2],h[3])
    end
    return h.pack("V4")
  end
  def self.md4(string)
    return fixed_md4(self.MDpad(string,:little),
                     [0x67452301, 
                      0xefcdab89,
                      0x98badcfe,
                      0x10325476])
  end
end
