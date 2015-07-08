require 'base64'

class Converters
  def self.hex_to_bytes(in_str)
    # Takes an input string and returns a byte array
    unless in_str.size % 2 == 0
      puts in_str.size
      raise "Hex string must contain pairs of hex digits"
    end
    if in_str =~ /[^0-9A-Fa-f]/
      raise "String contains non-hex characters!"
    end
    [in_str].pack('H*')
  end
  def self.str_to_hex(in_str)
    in_str.unpack('H*').first
  end
  def self.hex_to_base64(in_str)
    Base64.strict_encode64(hex_to_bytes(in_str))
  end
  def self.base64_to_hex(in_str)
    str_to_hex(Base64.decode64(in_str))
  end
  # these were adapted from https://stackoverflow.com/questions/9695720/how-do-i-convert-a-64bit-integer-to-a-char-array-and-back
  def self.str_to_int(str)
    bytes=str.bytes
    n = 0
    table=[0xFF00000000000000,
           0x00FF000000000000,
           0x0000FF0000000000,
           0x000000FF00000000,
           0x00000000FF000000,
           0x0000000000FF0000,
           0x000000000000FF00,
           0x00000000000000FF]
    8.times do |i| 
      n = n | ((bytes[i] << 8*(7-i)) & table[i])
    end
    return n
  end
  def self.int_to_str(num)
    bytes=[]
    8.times do |i| 
      bytes[i]=(num >> 8*(7-i))
    end
    return bytes.pack("C*")
  end
end
