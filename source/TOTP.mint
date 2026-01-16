module TOTP {
  /*
  Converts a time-step counter to an 8-byte big-endian array.

  TODO: Find a better home for this function.
  */
  fun timeCounterToBytes (counter : Number) : Array(Number) {
    `
    (() => {
      const bytes = new Array(8).fill(0);
      let value = Math.floor(#{counter});

      for (let i = 7; i >= 0; i--) {
        bytes[i] = value & 0xff;
        value = value >>> 8;
      }

      return bytes;
    })()
    `
  }

  /*
  Generates an HMAC-SHA signature using SubtleCrypto.

  Returns Promise with Result containing the HMAC signature bytes or error.

  TODO: Create a crypto package using SubtleCrypto and move this there.
  */
  fun hmacSha (
    algorithm : TOTP.Algorithm,
    key : Array(Number),
    message : Array(Number)
  ) : Promise(Result(TOTP.Error, Array(Number))) {
    let name =
      case algorithm {
        TOTP.Algorithm.SHA256 => "SHA-256"
        TOTP.Algorithm.SHA512 => "SHA-512"
        TOTP.Algorithm.SHA1 => "SHA-1"
      }

    `
    (async () => {
      try {
        const key =
          await crypto.subtle.importKey(
            'raw', new Uint8Array(#{key}),
            { name: 'HMAC', hash: #{name} },
            false, ['sign']
          );

        const signature =
          await crypto.subtle.sign('HMAC', key, new Uint8Array(#{message}));

        const signatureArray =
          Array.from(new Uint8Array(signature));

        return #{Result.Ok(`signatureArray`)};
      } catch (error) {
        return #{Result.Err(TOTP.Error.CryptoError(`error.message`))};
      }
    })()
    `
  }

  /*
  Dynamic truncation per RFC 6238.

  Takes an HMAC result and extracts a variable-length code.
  */
  fun truncate (hmac : Array(Number), digits : Number) : String {
    `
    (() => {
      const offset =
        #{hmac}[#{hmac}.length - 1] & 0x0f;

      const binary =
        (((#{hmac}[offset] & 0x7f) << 24) |
        ((#{hmac}[offset + 1] & 0xff) << 16) |
        ((#{hmac}[offset + 2] & 0xff) << 8) |
        (#{hmac}[offset + 3] & 0xff)) >>> 0;

      const modulo =
        Math.pow(10, #{digits});

      const code =
        (binary % modulo).toString();

      return code.padStart(#{digits}, '0');
    })()
    `
  }

  /* Generates a TOTP code. */
  fun generateCode (
    config : TOTP.Config,
    secretBytes : Array(Number),
    counter : Number
  ) : Promise(Result(TOTP.Error, String)) {
    let result =
      hmacSha(config.algorithm, secretBytes, timeCounterToBytes(counter))

    case await result {
      Ok(hmac) => Result.Ok(truncate(hmac, config.digits))
      Err(error) => Result.Err(error)
    }
  }

  /* Generates a TOTP code for a specific timestamp. */
  fun generateAt (
    config : TOTP.Config,
    timestamp : Number
  ) : Promise(Result(TOTP.Error, String)) {
    case Base32.decode(config.secret) {
      Err => Result.Err(TOTP.Error.InvalidSecret)

      Ok(secretBytes) =>
        await generateCode(config, secretBytes,
          Math.floor(timestamp / config.period))
    }
  }

  /* Generates a TOTP code for the current time. */
  fun generate (config : TOTP.Config) : Promise(Result(TOTP.Error, String)) {
    generateAt(config, Time.toUnix(Time.now()) / 1000)
  }

  /* Generates a TOTP code using default settings (SHA1, 6 digits, 30s period). */
  fun generateWithDefaults (
    secret : String
  ) : Promise(Result(TOTP.Error, String)) {
    generate(
      { secret: secret, algorithm: TOTP.Algorithm.SHA1, digits: 6, period: 30 })
  }

  /*
  Verifies a TOTP code against the current time with optional time window.

  The window parameter specifies how many adjacent periods to check:
  - window = 0: only check current period
  - window = 1: check previous, current, and next periods (3 total)
  - window = 2: check 2 periods back, current, and 2 periods forward (5 total)

  Returns Ok(true) if code is valid, Ok(false) if invalid, or Err if operation failed.
  */
  fun verify (
    config : TOTP.Config,
    code : String,
    window : Number = 1
  ) : Promise(Result(TOTP.Error, Bool)) {
    let now =
      Time.toUnix(Time.now()) / 1000

    let counter =
      `Math.floor(#{now} / (#{config.period}))`

    // Check current period and surrounding periods
    let results =
      (await for i of Array.range(`-#{window}`, `#{window} + 1`) {
        let timestamp =
          `(#{counter} + #{i}) * (#{config.period})`

        case await generateAt(config, timestamp) {
          Ok(generatedCode) => Maybe.Just(generatedCode == code)
          Err(error) => Maybe.Nothing
        }
      })
      |> Array.compact

    // If any errors occurred (empty results), return error
    if Array.size(results) > 0 {
      Result.Ok(Array.any(results, (item : Bool) { item }))
    } else {
      Result.Err(TOTP.Error.VerificationFailed)
    }
  }
}
