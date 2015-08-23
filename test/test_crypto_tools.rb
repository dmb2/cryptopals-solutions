require 'minitest/autorun'
require 'block_crypto'
require 'crypto_tools'
require 'stream_cipher'
class CryptoToolsTest < MiniTest::Test
  def test_xor_key
    assert_equal Converters.str_to_hex(CryptoTools.xor_key("Hello World","ICE")), "012629252c651e2c372527"
  end
  def test_pearson_chi2
    english_freq={"a" => 0.0651738, "b" => 0.0124248, "c" => 0.0217339,
                  "d" => 0.0349835, "e" => 0.1041442, "f" => 0.0197881,
                  "g" => 0.0158610, "h" => 0.0492888, "i" => 0.0558094,
                  "j" => 0.0009033, "k" => 0.0050529, "l" => 0.0331490,
                  "m" => 0.0202124, "n" => 0.0564513, "o" => 0.0596302,
                  "p" => 0.0137645, "q" => 0.0008606, "r" => 0.0497563,
                  "s" => 0.0515760, "t" => 0.0729357, "u" => 0.0225134,
                  "v" => 0.0082903, "w" => 0.0171272, "x" => 0.0013692,
                  "y" => 0.0145984, "z" => 0.0007836, " " => 0.1918182}
    assert_equal CryptoTools.pearson_chi2(english_freq,english_freq), 0
    assert_equal CryptoTools.pearson_chi2(Hash.new(0),english_freq), 1
  end
  def test_break_xor
    assert_equal CryptoTools.break_xor(CryptoTools.xor_key("Alice was beginning to get very tired of sitting by her sister on the bank","I"))[0],"I"
  end
  def test_hamming_dist
    assert_equal CryptoTools.hamming_distance("this is a test","wokka wokka!!!"),37
  end
  def test_nbits
    assert_equal CryptoTools.nbits(31415926),18
  end
  def test_detect_aes_ecb
    input=BlockCrypto.AES_128_ECB("A"*256,"A"*16)
    output=CryptoTools.detect_aes_ecb(input)
    assert_equal input,output
  end
  def test_undiffuse
    y=(0xFFFFFFFF-1)
    c=17
    b=0x9d2c5680
    mtrng=MersenneTwisterRng.new(1234)
    # diffused=mtrng.diffuse(y,c,b,:left)
    # assert_equal y,CryptoTools.undiffuse(diffused,c,b)
    diffused=mtrng.diffuse(y,c,b,:right)
    assert_equal CryptoTools.undiffuse(diffused,c,b),y
  end
  # def test_untemper
  #   y=223154134
  #   mtrng=MersenneTwisterRng.new(1234)
  #   tempered=mtrng.temper(y)
  #   assert_equal CryptoTools.untemper(y),y
  # end
end

class ConvertersTest < MiniTest::Test
  def test_hex_to_bytes
    assert_equal Converters.hex_to_bytes("48656c6c6f20576f726c64") ,
                 "Hello World"
  end
  def test_str_to_hex 
    assert_equal Converters.str_to_hex("Hello World"),
                 "48656c6c6f20576f726c64"
  end
  def test_hex_to_base64
    assert_equal Converters.hex_to_base64("48656c6c6f20576f726c64"),
                 "SGVsbG8gV29ybGQ="
  end
  def test_base64_to_hex
    assert_equal Converters.base64_to_hex("SGVsbG8gV29ybGQ="),
                 "48656c6c6f20576f726c64"
  end
end

class BlockCryptoTest < MiniTest::Test
  def test_pkcs7pad
    assert_equal Converters.str_to_hex("Hello World".pkcs7pad(16)),
                 "48656c6c6f20576f726c640505050505"
  end
  def test_pkcs7strip
    assert_equal "Hello World".pkcs7pad(16).pkcs7strip, "Hello World"
  end
  def test_aes_cbc_encrypt_decrypt
      key="YELLOW SUBMARINE"
      iv="0000000000000000"
      test_str="Alice was beginning to get very tired of sitting by her sister on the
bank, and of having nothing to do: once or twice she had peeped into the
book her sister was reading, but it had no pictures or conversations in
it, 'and what is the use of a book,' thought Alice 'without pictures or
conversations?'"
      cipher_text=BlockCrypto.aes_cbc_encrypt(test_str,key,iv)
      clear_text=BlockCrypto.aes_cbc_decrypt(cipher_text,key,iv)
      assert_equal clear_text,test_str
  end
  def test_random_byte_string
    rand_string = BlockCrypto.random_byte_string(17)
    assert_equal 17,rand_string.length
  end
end
class StreamCryptoTest < MiniTest::Test
  def test_aes_ctr_encrypt_decrypt
    nonce="\0"*8
    key="YELLOW SUBMARINE"
    test_str="Alice was beginning to get very tired of sitt
ing by her sister on the
bank, and of having nothing to do: once or twice she had peeped into the
book her sister was reading, but it had no pictures or conversations in
it, 'and what is the use of a book,' thought Alice 'without pictures or
conversations?'"
    encrypted=StreamCrypto.aes_ctr_encrypt(test_str,nonce,key)
    assert_equal StreamCrypto.aes_ctr_decrypt(encrypted,nonce,key),test_str
  end
end 
class MersenneTwisterTest < MiniTest::Test
  def test_mersene_twister_rng
    mtrng=MersenneTwisterRng.new(1234)
    prng=Random.new(1234)
    mtrng_vals=[]
    prng_vals=[]
    # Tap the rng 5 times to make sure that its state gets twisted at
    # least 5 times
    (624*5).times do 
      mtrng_vals+=[prng.rand(2**32)]
      prng_vals+=[mtrng.extract_number]
    end
    assert_equal mtrng_vals,prng_vals
  end
end

