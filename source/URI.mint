module TOTP.URI {
  /*
  Generates an `otpauth://` URL for use with authenticator apps.

  The URL can be converted to a QR code for easy scanning by authenticator apps
  like Google Authenticator, Authy, Microsoft Authenticator, etc.
  */
  fun generate (config : TOTP.OTPAuthConfig) : String {
    let algorithm =
      case config.algorithm {
        TOTP.Algorithm.SHA256 => "SHA-256"
        TOTP.Algorithm.SHA512 => "SHA-512"
        TOTP.Algorithm.SHA1 => "SHA-1"
      }

    let encodedIssuer =
      `encodeURIComponent(#{config.issuer})`

    let encodedAccount =
      `encodeURIComponent(#{config.accountName})`

    let label =
      "#{encodedIssuer}:#{encodedAccount}"

    let params =
      SearchParams.empty()
      |> SearchParams.append("digits", Number.toString(config.digits))
      |> SearchParams.append("period", Number.toString(config.period))
      |> SearchParams.append("secret", config.secret)
      |> SearchParams.append("issuer", config.issuer)
      |> SearchParams.append("algorithm", algorithm)
      |> SearchParams.toString()

    "otpauth://totp/#{label}?#{params}"
  }

  /* Generates an `otpauth://` URL using default settings (SHA1, 6 digits, 30s period). */
  fun generateWithDefaults (
    secret : String,
    issuer : String,
    accountName : String
  ) : String {
    generate(
      {
        algorithm: TOTP.Algorithm.SHA1,
        accountName: accountName,
        secret: secret,
        issuer: issuer,
        period: 30,
        digits: 6
      })
  }
}
