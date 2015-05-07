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
end
