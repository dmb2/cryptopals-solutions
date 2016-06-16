require 'pubkey'
require 'converters'
require 'securerandom'
class DiffieHellmanPeer
  attr_reader :aes_key
  def initialize(name,p,g)
    @name = name
    @dh_key = DiffieHellman.new(p,g)
    @peer = nil
    @aes_key = nil
  end
  def to_s
    "name: #{@name}, aes_key: #{@aes_key!=nil ? @aes_key.unpack("H*")[0] : "nil"}\n"
  end
  def key_exchange
    @peer.handshake("#{@dh_key.P},#{@dh_key.G},#{@dh_key.pub_key}")
  end
  def handshake(dh_param_str)
    params = dh_param_str.split(",")
    if params.length!=3 and params.length!=1
      raise "Handshake failed, mangled string: #{dh_param_str}"
    elsif params.length==1
      @aes_key=@dh_key.sha1_session(dh_param_str.to_i)
      # puts "#{@name}'s shared aes key: #{@aes_key.unpack("H*")[0]}"
    else
      @dh_key = DiffieHellman.new(params[0].to_i,params[1].to_i)
      @aes_key=@dh_key.sha1_session(params[2].to_i)
      @peer.handshake("#{@dh_key.pub_key}")
      # puts "#{@name}'s shared aes key: #{@aes_key.unpack("H*")[0]}"
    end
  end
  def connect(peer)
    @peer = peer
  end
  def close_connection
    @peer = nil
    @aes_key=nil
  end
  def aes_decrypt(message)
    aes = OpenSSL::Cipher.new 'AES-128-CBC'
    aes.decrypt
    iv = message.slice!(-16,16)
    aes.iv=iv
    aes.key=@aes_key
    aes.update(message)+aes.final
  end
  def aes_encrypt(message)
    aes = OpenSSL::Cipher.new 'AES-128-CBC'
    aes.encrypt
    iv = aes.random_iv
    aes.iv=iv
    aes.key=@aes_key
    aes.update(message)+aes.final+iv
  end
  def send(message)
    ct = self.aes_encrypt(message)
    # puts "#{@name} sends: #{message}"
    @peer.recieve(ct)
  end
  def recieve(message)
    pt = self.aes_decrypt(message)
    # puts "#{@name} recieved #{message.unpack("H*")[0]}"
    # puts "#{@name}: decrypted: #{pt}"
  end
end
class DiffieHellmanEcho < DiffieHellmanPeer
 def recieve(message)
    pt = self.aes_decrypt(message)
    # puts "#{@name}: decrypted: #{pt}"
    self.send(pt)
 end 
end
class DiffieHellmanMITM < DiffieHellmanPeer
  def initialize(name,p,g)
    @name = name
    @dh_key = DiffieHellman.new(p,g)
    @aes_key = Digest::SHA1.digest([0].pack("C*"))
    @alice = nil
    @bob = nil
  end
  def key_exchange
    @bob.handshake("#{@dh_key.P},#{@dh_key.G},#{@dh_key.P}")
    @alice.handshake("#{@dh_key.P}")
  end
  def send(message)
    ct = self.aes_encrypt(message)
    @bob.recieve(ct)
  end
  def recieve(message)
    pt = self.aes_decrypt(message)
    # puts "#{@name}: decrypted: #{pt}"
  end
  def handshake(dh_params)
  end
  def connect(peer)
    if @alice == nil
      @alice = peer
    else
      @bob = peer
    end
  end
  def to_s
    "name: #{@name} aes_key: #{@aes_key}\n\talice: #{@alice}\n\tbob: #{@bob}"
  end
end


class DHGroups < DiffieHellmanPeer
  def key_exchange
    @peer.handshake("#{@dh_key.P},#{@dh_key.G}")
  end
  def handshake(dh_params)
    params = dh_params.split(",")
    if params.length==2
      # puts "#{@name} received #{dh_params.inspect}"
      @dh_key = DiffieHellman.new(params[0].to_i,params[1].to_i)
      @peer.handshake([6].pack("C*"))
    elsif params[0]==[6].pack("C*")
      # puts "#{@name} received #{dh_params.inspect}"
      @peer.handshake("#{@dh_key.pub_key}")
    else
      # puts "#{@name} received #{dh_params.inspect}"
      @aes_key=@dh_key.sha1_session(dh_params.to_i)
      if @peer.aes_key==nil
        @peer.handshake("#{@dh_key.pub_key}")
      end
      # puts "#{@name}'s shared aes key: #{@aes_key.unpack("H*")[0]}"
    end
  end
end

class DHGroupsMITM < DHGroups
  
  def initialize(name,p,g)
    @name = name
    @dh_key = DiffieHellman.new(p,g)
    @aes_key = nil#Digest::SHA1.digest([g%p].pack("C*"))
    @alice = nil
    @bob = nil
  end
  def handshake(dh_params)
    params=dh_params.split(",")
    if params.length == 2
      @alice.handshake("#{@dh_key.P},#{@dh_key.G}")
      @bob.handshake("#{@dh_key.P},#{@dh_key.G}")
    elsif params[0]==[6].pack("C*")
      @alice.handshake("#{@dh_key.pub_key}")
      @bob.handshake("#{@dh_key.pub_key}")
    else
      @aes_key = @dh_key.sha1_session(dh_params.to_i)
    end
  end
  def connect(peer)
    if @alice == nil
      @alice = peer
    else
      @bob = peer
    end
  end
  def to_s
    "name: #{@name}, aes_key: #{@aes_key.unpack("H*")[0]}\n\talice: #{@alice}\n\tbob: #{@bob}"
  end
end
