require 'string_utils'
def sha1(message)
  h=[0x67452301,
     0xEFCDAB89,
     0x98BADCFE,
     0x10325476,
     0xC3D2E1F0]
  char_size=message.bytes[0].bit_length
  ml = char_size*message.length
  # preprocessing
  if ml%8==0
    message=(message.bytes+[0x80]).pack("C*")
  end
  # pad the message to a multiple of 512 bits
  bytelen=512/char_size
  bytes=message.bytes
  pad_length = bytelen - (bytes.length%bytelen)
  padded_message = (bytes +[0]*pad_length).pack("C*")
  padded_message.blocks(bytelen).each do |chunk| 
    chunk.blocks(32)
  end
  
end
