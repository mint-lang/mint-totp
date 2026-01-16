suite "TOTP Tests" {
  /*
  RFC 6238 defines official test vectors for validating TOTP implementations.
  See: https://tools.ietf.org/html/rfc6238#appendix-b

  All test vectors use the shared secret: "12345678901234567890"
  In base32 encoding: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

  The tests below validate the core TOTP generation with known timestamps
  and expected outputs.
  */
  test "RFC 6238 SHA1 test vector (59 seconds)" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        algorithm: TOTP.Algorithm.SHA1,
        digits: 8,
        period: 30
      }

    case await TOTP.generateAt(config, 59) {
      Ok("94287082") => true
      Ok(code) => false
      Err(error) => false
    }
  }

  test "RFC 6238 SHA256 test vector (59 seconds)" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
        algorithm: TOTP.Algorithm.SHA256,
        digits: 8,
        period: 30
      }

    case await TOTP.generateAt(config, 59) {
      Ok("46119246") => true
      Ok(code) => false
      Err(error) => false
    }
  }

  test "RFC 6238 SHA512 test vector (59 seconds)" {
    let config =
      {
        secret:
          "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
        algorithm: TOTP.Algorithm.SHA512,
        digits: 8,
        period: 30
      }

    case await TOTP.generateAt(config, 59) {
      Ok("90693936") => true
      Ok(code) => false
      Err(error) => false
    }
  }

  test "RFC 6238 SHA1 test vector (1111111109 seconds)" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        algorithm: TOTP.Algorithm.SHA1,
        digits: 8,
        period: 30
      }

    case await TOTP.generateAt(config, 1111111109) {
      Ok("07081804") => true
      Ok(code) => false
      Err(error) => false
    }
  }

  test "RFC 6238 SHA256 test vector (1111111109 seconds)" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
        algorithm: TOTP.Algorithm.SHA256,
        digits: 8,
        period: 30
      }

    case await TOTP.generateAt(config, 1111111109) {
      Ok("68084774") => true
      Ok(code) => false
      Err(error) => false
    }
  }

  test "RFC 6238 SHA512 test vector (1111111109 seconds)" {
    let config =
      {
        secret:
          "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
        algorithm: TOTP.Algorithm.SHA512,
        digits: 8,
        period: 30
      }

    case await TOTP.generateAt(config, 1111111109) {
      Ok("25091201") => true
      Ok(code) => false
      Err(error) => false
    }
  }

  test "generate - creates valid 6-digit codes" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        algorithm: TOTP.Algorithm.SHA1,
        digits: 6,
        period: 30
      }

    case await TOTP.generate(config) {
      Ok(code) => String.size(code) == 6
      Err(error) => false
    }
  }

  test "generate - creates valid 8-digit codes" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        algorithm: TOTP.Algorithm.SHA1,
        digits: 8,
        period: 30
      }

    case await TOTP.generate(config) {
      Ok(code) => String.size(code) == 8
      Err(error) => false
    }
  }

  test "TOTP.generateWithDefaults - generates with defaults" {
    case await TOTP.generateWithDefaults("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") {
      Ok(code) => String.size(code) == 6
      Err(error) => false
    }
  }

  test "verify - accepts valid code with window" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        algorithm: TOTP.Algorithm.SHA1,
        digits: 6,
        period: 30
      }

    case await TOTP.generate(config) {
      Ok(code) =>
        case await TOTP.verify(config, code, 1) {
          Ok(true) => true
          Ok(false) => false
          Err(error) => false
        }

      Err(error) => false
    }
  }

  test "verify - rejects invalid code" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        algorithm: TOTP.Algorithm.SHA1,
        digits: 6,
        period: 30
      }

    case await TOTP.verify(config, "000000", 1) {
      Ok(false) => true
      Ok(true) => false
      Err(error) => false
    }
  }

  test "Base32.decode - decodes valid base32" {
    case Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") {
      Ok(bytes) => Array.size(bytes) > 0
      Err(error) => false
    }
  }

  test "Base32.decode - rejects invalid base32 characters" {
    case Base32.decode("INVALID!!!CHARACTERS!!!") {
      Err(InvalidCharacter) => true
      Ok(bytes) => false
      Err(error) => false
    }
  }

  test "TOTP.URI.generate - creates valid otpauth URL" {
    let config =
      {
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        issuer: "Example Corp",
        accountName: "user@example.com",
        algorithm: TOTP.Algorithm.SHA1,
        digits: 6,
        period: 30
      }

    let url =
      TOTP.URI.generate(config)

    String.startsWith(url, "otpauth://totp/") && String.contains(url,
      "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") && String.contains(url,
      "issuer=") && String.contains(url, "algorithm=SHA-1") && String.contains(
      url, "digits=6") && String.contains(url, "period=30")
  }

  test "TOTP.URI.generateWithDefaults - creates URL with defaults" {
    let url =
      TOTP.URI.generateWithDefaults("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "Example", "test@example.com")

    String.contains(url, "otpauth://totp/") && String.contains(url,
      "algorithm=SHA-1") && String.contains(url, "digits=6") && String.contains(
      url, "period=30")
  }
}
