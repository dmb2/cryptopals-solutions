require 'converters'

def hex_xor(hex_a,hex_b)
  if hex_a.length != hex_b.length
    raise "Length of hex strings doesn't match!"
  end
  bytes_a = hex_to_bytes(hex_a).bytes
  bytes_b = hex_to_bytes(hex_b).bytes
  str_to_hex(bytes_a.zip(bytes_b).map{ |x,y| x^y }.pack("C*"))
end

def hex_xor_key(hex_in,xor_key)
  key_str=""
  (Float(hex_in.length)/xor_key.length).ceil().times{ key_str+=xor_key }
  hex_xor(hex_in,key_str.slice(0,hex_in.length))
end
def freq_hist(test_str)
  hist = Hash.new(0)
  sani_str=test_str.scan(/[A-Za-z]/).join.downcase
  sani_str.each_char {|c| 
    hist[c]+=1
  }
  hist
end
def pearson_chi2(observed,expected)
  chi2=0
  ndof=0
  observed.keys.each{ |c| 
    ndof+=1
    chi2+=(observed[c]-expected[c])**2/expected[c]
  }
  chi2/ndof
end
def score_string(raw_string)
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
def break_xor(cipher_hex)
  key=''
  minscore=10000
  for c in 48..126
    result = hex_xor_key(cipher_hex,str_to_hex(c.chr.to_s))
    ascii_res = hex_to_bytes(result)
    # if ascii_res =~ /[^[:print:]]/
    #   next
    # end
    score=score_string(ascii_res)
    if score < minscore
      minscore=score
      key=c.chr.to_s
    end
  end
  puts minscore
  key
end

def str_xor_key(str,key)
  hex_xor_key(str_to_hex(str),str_to_hex(key))
end
