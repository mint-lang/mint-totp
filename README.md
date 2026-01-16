# TOTP (Time-Based One-Time Password)

A Mint package providing RFC 6238-compliant TOTP code generation for two-factor authentication.

## Features

- Support for SHA-1, SHA-256, and SHA-512 hash algorithms
- Configurable code length (6, 8, or any digit count)
- Configurable time period (default 30 seconds)
- Generate `otpauth://` URLs for QR code generation
- Verify TOTP codes with configurable time window support
- Zero external dependencies (uses Web Crypto API)

## Installation

Add to your `mint.json` dependencies:

```json
{
  "dependencies": {
    "totp": {
      "repository": "https://github.com/mint-lang/mint-totp",
      "constraint": "0.0.0 <= v < 1.0.0"
    }
  }
}
```

## Basic Usage

### Generate Current Code

```mint
component AuthenticatorDemo {
  fun onGenerate {
    case await TOTP.generateWithDefaults("JBSWY3DPEHPK3PXP") {
      Ok(code) =>
        Debug.log("Current TOTP code: #{code}")

      Err(error) =>
        Debug.log("Error generating code")
    }
  }

  fun render {
    <button onClick={onGenerate}>
      "Generate Code"
    </button>
  }
}
```

### Advanced Configuration

```mint
{
  let config = {
    algorithm: Totp.Algorithm.SHA256,
    secret: "JBSWY3DPEHPK3PXP",
    period: 30,
    digits: 8
  }

  case await Totp.generate(config) {
    Ok(code) =>
      // Use 8-digit SHA256 code
      Debug.log("Code: #{code}")

    Err(Totp.Error.InvalidSecret(msg)) =>
      // Handle invalid base32 secret
      Debug.log("Invalid secret: #{msg}")

    Err(error) =>
      // Handle other errors
      Debug.log("Error")
  }
}
```

### Generate QR Code URL

```mint
{
  let url = TOTP.URI.generateWithDefaults(
    "JBSWY3DPEHPK3PXP",
    "MyApp",
    "user@example.com"
  )

  // url = "otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp&algorithm=SHA1&digits=6&period=30"
  // Convert to QR code and display to user for setup
}
```

### Verify User Input

```mint
{
  let config = {
    algorithm: Totp.Algorithm.SHA1,
    secret: "JBSWY3DPEHPK3PXP",
    period: 30,
    digits: 6
  }

  case await Totp.verify(config, userInput, 1) {
    Ok(true) =>
      // Code is valid - allow login
      Debug.log("Authentication successful")

    Ok(false) =>
      // Code is invalid - reject
      Debug.log("Invalid code")

    Err(error) =>
      // Handle error
      Debug.log("Verification error")
  }
}
```

## Testing

Run tests with RFC 6238 official test vectors:

```bash
mint test
```

All tests validate against the official RFC 6238 test vectors to ensure correctness.

## References

- [RFC 6238 - TOTP: Time-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc4226)
- [RFC 4648 - The Base16, Base32, and Base64 Data Encodings](https://tools.ietf.org/html/rfc4648)
