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
    sani_str=test_str.scan(/[A-Za-z]/).join
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
    ndof=1
    expected.keys.each{ |c| 
      ndof+=1
      chi2+=(observed[c]-expected[c])**2/expected[c]
    }
    if observed.keys.length == 0
      chi2=1000
    end
    chi2/ndof
  end
  def self.score_string(raw_string)
    # english_freq={'a' => 0.08167, 'b' => 0.01492,
    #               'c' => 0.02782, 'd' => 0.04253,
    #               'e' => 0.12702, 'f' => 0.02228,
    #               'g' => 0.02015, 'h' => 0.06094,
    #               'i' => 0.06966, 'j' => 0.00153,
    #               'k' => 0.00772, 'l' => 0.04025,
    #               'm' => 0.02406, 'n' => 0.06749,
    #               'o' => 0.07507, 'p' => 0.01929, 
    #               'q' => 0.00095, 'r' => 0.05987,
    #               's' => 0.06327, 't' => 0.09056,
    #               'u' => 0.02758, 'v' => 0.00978,
    #               'w' => 0.02361, 'x' => 0.00150,
    #               'y' => 0.01974, 'z' => 0.00074,
    #               ' ' => 0.18525}
    english_freq= {" "=>0.16693430439065157,
                   "A"=>0.004304092170850372,
                   "B"=>0.0007462018326717011,
                   "C"=>0.0011043787123541176,
                   "D"=>0.0014446467480524131,
                   "E"=>0.0018684893890099394,
                   "F"=>0.0007999283646240636,
                   "G"=>0.0011521356296451063,
                   "H"=>0.001844610930364445,
                   "I"=>0.004960749783601469,
                   "J"=>7.760499059785691e-05,
                   "K"=>0.0005253260902008775,
                   "L"=>0.0009431991164970302,
                   "M"=>0.001325254454824941,
                   "N"=>0.0010864698683699966,
                   "O"=>0.0013968898307614244,
                   "P"=>0.0010267737217562606,
                   "Q"=>0.0005074172462167568,
                   "R"=>0.001265558308211205,
                   "S"=>0.0017192490224755992,
                   "T"=>0.0034086499716443302,
                   "U"=>0.0006626272274124705,
                   "V"=>0.00031041996239142766,
                   "W"=>0.0015282213533116438,
                   "X"=>3.581768796824165e-05,
                   "Y"=>0.0008476852819150524,
                   "Z"=>5.9696146613736086e-06,
                   "a"=>0.05421007073993374,
                   "b"=>0.00967674536608662,
                   "c"=>0.016804465271766707,
                   "d"=>0.03120317583499985,
                   "e"=>0.09002775870817539,
                   "f"=>0.013419693758767871,
                   "g"=>0.016416440318777422,
                   "h"=>0.04524967913321195,
                   "i"=>0.04657493358803689,
                   "j"=>0.001325254454824941,
                   "k"=>0.007175476822971078,
                   "l"=>0.030164462883920842,
                   "m"=>0.01340178491478375,
                   "n"=>0.046974897770348925,
                   "o"=>0.05518311792973764,
                   "p"=>0.010721427931827001,
                   "q"=>0.0008058979792854371,
                   "r"=>0.03819359460346835,
                   "s"=>0.04166194072172641,
                   "t"=>0.06942064889711369,
                   "u"=>0.023084499895531744,
                   "v"=>0.005438318956511357,
                   "w"=>0.01609408112706325,
                   "x"=>0.0010148344924335135,
                   "y"=>0.014577799003074352,
                   "z"=>0.0004715995582485151,
                  }
    hist=freq_hist(raw_string)
    pearson_chi2(hist,english_freq)
  end
  def self.break_xor(cipher_hex)
    key=''
    minscore=10000
    for c in 32..126
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
  def self.find_keylen(cipher_byte_str)
    keylen=0
    minavg=1e10
    2.upto(40){ |kl|
      sample=[]
      25.times{ |i|
        sample+=[hamming_distance(cipher_byte_str.slice(i*kl,kl),
                                  cipher_byte_str.slice((i+1)*kl,kl))/Float(kl)]
      }
      average=0
      sample.each{ |val| average+=val }
      average/=sample.length
      if average < minavg
        minavg=average
        keylen=kl
      end
    }
    return keylen
  end
  def self.break_xor_key(cipher_text,keylen)
    blocks=[]
    key_str=""
    (Float(cipher_text.length)/keylen).floor().times{ |i|
      blocks+=[cipher_text.slice(keylen*i,keylen).bytes]
    }
    blocks.transpose.each { |list|
      key,score=break_xor(Converters.str_to_hex(list.pack("C*")))
      key_str+=key
      # puts sprintf "%s %.3g",key,score
    }
    return key_str
  end
end


