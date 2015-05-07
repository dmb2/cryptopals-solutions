require 'minitest/autorun'
require 'crypto_tools'

class CryptoToolsTest < MiniTest::Test
  def test_str_xor_key
    assert_equal CryptoTools.str_xor_key("Hello World","ICE"), "012629252c651e2c372527"
  end
  def test_break_xor
    assert_equal CryptoTools.break_xor(CryptoTools.str_xor_key("Hello World","I"))[0],"I"
  end
  def test_hamming_dist
    assert_equal CryptoTools.hamming_distance("this is a test","wokka wokka!!!"),37
  end
  def test_nbits
    assert_equal CryptoTools.nbits(31415926),18
  end
end

class ConvertersTest < MiniTest::Test
  def test_hex_to_bytes
    assert_equal Converters.hex_to_bytes("48656c6c6f20576f726c64") , "Hello World"
  end
  def test_str_to_hex 
    assert_equal Converters.str_to_hex("Hello World"), "48656c6c6f20576f726c64"
  end
  def test_hex_to_base64
    assert_equal Converters.hex_to_base64("48656c6c6f20576f726c64"), "SGVsbG8gV29ybGQ="
  end
  def test_base64_to_hex
    assert_equal Converters.base64_to_hex("SGVsbG8gV29ybGQ="), "48656c6c6f20576f726c64"
  end
end

