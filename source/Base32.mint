type Base32.Error {
  InvalidCharacter(Number, String)
  Invalid
}

// TODO: Move to core library.
module Base32 {
  fun decode (input : String) : Result(Base32.Error, Array(Number)) {
    `
    (() => {
      const DICTIONARY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      const input = #{input}.toUpperCase().replace(/=+$/, '');

      let bits = '';

      for (let index = 0; index < input.length; index++) {
        const char = input[index];

        if (DICTIONARY.indexOf(char) === -1) {
          return #{Result.Err(Base32.Error.InvalidCharacter(`index`, `char`))};
        } else {
          const base32Index = DICTIONARY.indexOf(char);
          bits += base32Index.toString(2).padStart(5, '0');
        }
      }

      // Convert bits to bytes (every 8 bits)
      const bytes = [];

      for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substr(i, 8), 2));
      }

      if (bytes.length === 0) {
        return #{Result.Err(Base32.Error.Invalid)};
      }

      return #{Result.Ok(`bytes`)};
    })()
    `
  }
}
