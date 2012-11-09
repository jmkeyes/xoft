class Xoft
  CONV_TABLE = ('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a + [ '+', '/' ]

  def initialize(key = nil)
    @key = key
  end

  def encode(plaintext)
    plaintext.bytes.zip(keystream).inject([]) do |result, (data, key)|
      value = ((data ^ key) + @key.length)
      result << ((value & 0xf0) >> 2) << ((value & 0x0f) << 2)
    end.zip(modifier).inject('') do |result, (data, mod)|
      result << CONV_TABLE[(data + mod)]
    end
  end

  def decode(ciphertext)
    ciphertext.bytes.zip(modifier).inject([]) do |result, (data, mod)|
      result << (CONV_TABLE.index((data - mod).chr) >> 2)
    end.each_slice(2).zip(keystream).inject('') do |result, ((upper, lower), key)|
      result << (((upper << 4 | lower) - @key.length) ^ key)
    end
  end

  private
  def keystream
    raise ArgumentError, "Must have an encryption key set in order to operate!" unless @key
    @keystream ||= @key.bytes.cycle
  end

  def modifier
    @modifier ||= (0..3).cycle
  end
end
