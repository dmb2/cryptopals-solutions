Gem::Specification.new do |s| 
  s.name = 'crypto_tools'
  s.version = '0.0.5'
  s.executables << 'challenge_set1'
  s.executables << 'challenge_set2'
  s.executables << 'challenge_set3'
  s.executables << 'challenge_set4'
  s.executables << 'challenge_set5'
  s.executables << 'diffie_hellman_server'
  s.date = '2015-05-06'
  s.summary = 'Solutions to Matasano Cryptography challenges'
  s.description = 'Tools for completing Matasano\'s crypto challenges'
  s.authors = ["David Bjergaard"]
  s.email = 'dbjergaard@gmail.com'
  s.files = ["lib/converters.rb",
             "lib/string_utils.rb",
             "lib/servers.rb",
             "lib/dh_clients.rb",
             "lib/hash_functions.rb",
             "lib/stream_cipher.rb",
             "lib/block_crypto.rb",
             "lib/crypto_tools.rb",
             "lib/pubkey.rb",
             "lib/srp_server.rb"
            ]
  s.homepage = 'https://dbjergaard.github.io/'
  s.license = 'MIT'
end
