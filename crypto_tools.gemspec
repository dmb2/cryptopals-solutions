Gem::Specification.new do |s| 
  s.name = 'crypto_tools'
  s.version = '0.0.4'
  s.executables << 'challenge_set1'
  s.executables << 'challenge_set2'
  s.executables << 'challenge_set3'
  s.executables << 'challenge_set4'
  s.date = '2015-05-06'
  s.summary = 'Cryptography and pen testing tools'
  s.description = 'Tools for completing matasano\'s crypto challenges'
  s.authors = ["David Bjergaard"]
  s.email = 'dbjergaard@gmail.com'
  s.files = ["lib/converters.rb",
             "lib/string_utils.rb",
             "lib/servers.rb",
             "lib/hash_functions.rb",
             "lib/stream_cipher.rb",
             "lib/block_crypto.rb",
             "lib/crypto_tools.rb"]
  s.homepage = 'https://dbjergaard.github.io/'
  s.license = 'MIT'
end
