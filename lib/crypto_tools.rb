require 'converters'
# class String
#   def chunk(i,n)
#     if i < 1
#       raise "Chunks are only defined for i >= 1"
#     end
#     if n < 0
#       raise "Negative chunk size has no meaning"
#     end
#     # puts sprintf "%d %d",n*(i-1),n
#     self.slice(n*(i-1),n)
#   end
# end

class CryptoTools 
  def self.hex_xor(hex_a,hex_b)
    if hex_a.length != hex_b.length
      raise "Length of hex strings doesn't match!"
    end
    # puts hex_a,hex_b
    bytes_a = Converters.hex_to_bytes(hex_a).bytes
    bytes_b = Converters.hex_to_bytes(hex_b).bytes
    Converters.str_to_hex(bytes_a.zip(bytes_b).map{ |x,y| x^y }.pack("C*"))
  end
  def self.hex_xor_key(hex_in,xor_key)
    key_str=""
    (Float(hex_in.length)/xor_key.length).ceil().times{ key_str+=xor_key }
    hex_xor(hex_in,key_str.slice(0,hex_in.length))
  end
  def self.freq_hist(test_str)
    hist = Hash.new(0)
    sani_str=test_str.scan(/[A-Za-z]/).join.downcase
    total=sani_str.length
    sani_str.each_char {|c| 
      hist[c]+=1
    }
    hist.each_key{ |k|
      hist[k]/=Float(total)
    }
  end
  def self.pearson_chi2(observed,expected)
    chi2=0
    expected.keys.each{ |c| 
      chi2+=(observed[c]-expected[c])**2/expected[c]
    }
    if observed.keys.length == 0
      chi2=1000
    end
    chi2
  end
  def self.score_string(raw_string)
    english_freq={'a' => 0.08167, 'b' => 0.01492,
                  'c' => 0.02782, 'd' => 0.04253,
                  'e' => 0.12702, 'f' => 0.02228,
                  'g' => 0.02015, 'h' => 0.06094,
                  'i' => 0.06966, 'j' => 0.00153,
                  'k' => 0.00772, 'l' => 0.04025,
                  'm' => 0.02406, 'n' => 0.06749,
                  'o' => 0.07507, 'p' => 0.01929, 
                  'q' => 0.00095, 'r' => 0.05987,
                  's' => 0.06327, 't' => 0.09056,
                  'u' => 0.02758, 'v' => 0.00978,
                  'w' => 0.02361, 'x' => 0.00150,
                  'y' => 0.01974, 'z' => 0.00074 }
    hist=freq_hist(raw_string)
    pearson_chi2(hist,english_freq)
  end
  def self.break_xor(cipher_hex)
    key=''
    minscore=10000
    for c in 48..126
      result = hex_xor_key(cipher_hex,Converters.str_to_hex(c.chr.to_s))
      ascii_res = Converters.hex_to_bytes(result)
      score=score_string(ascii_res)
      # puts sprintf "%.3f %s %s",score,c.chr.to_s,ascii_res
      if score < minscore
        minscore=score
        key=c.chr.to_s
      end
    end
    return key,score
  end

  def self.str_xor_key(str,key)
    hex_xor_key(Converters.str_to_hex(str), Converters.str_to_hex(key))
  end
  def self.nbits(value)
    tmp=value
    num=0
    while tmp != 0
      tmp &= (tmp - 1)
      num+=1
    end
    return num
  end
  def self.hamming_distance(str1,str2)
    if str1.length != str2.length
      raise "Hamming distance undefined for strings if differing lengths"
    end
    dist=0
    str1.bytes.zip(str2.bytes).each{|x,y|
      dist+=nbits(x^y)
    }
    return dist
  end
  def self.detect_xor(strings)
    minscore=1e10
    validkey=""
    validline=""
    strings.each_line{ |l|
      key,score = CryptoTools.break_xor(l.strip())
      ascii_res=Converters.hex_to_bytes(hex_xor_key(l.strip(),Converters.str_to_hex(key)))
      if ascii_res.strip.scan(/[^[:print:]]/).length > 0
        next
      end
      if score < minscore
        minscore=score
        validkey=key
        validline=ascii_res
      end
    }
    return validkey,validline
  end
end


