Gem::Specification.new do |s| 
  s.name = 'crypto_tools'
  s.version = '0.0.2'
  s.executables << 'challenge_set1'
  s.executables << 'challenge_set2'
  s.date = '2015-05-06'
  s.summary = 'Cryptography and pen testing tools'
  s.description = 'Tools for completing matasano\'s crypto challenges'
  s.authors = ["David Bjergaard"]
  s.email = 'dbjergaard@gmail.com'
  s.files = ["lib/converters.rb", "lib/servers.rb",
             "lib/block_crypto.rb","lib/crypto_tools.rb"]
  s.homepage = 'https://dbjergaard.github.io/'
  s.license = 'MIT'
end
