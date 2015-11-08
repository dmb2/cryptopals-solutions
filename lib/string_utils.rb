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
