type TOTP.Error {
  CryptoError(String)
  VerificationFailed
  InvalidSecret
}

type TOTP.Algorithm {
  SHA256
  SHA512
  SHA1
}

type TOTP.Config {
  algorithm : TOTP.Algorithm,
  secret : String,
  digits : Number,
  period : Number
}

type TOTP.OTPAuthConfig {
  algorithm : TOTP.Algorithm,
  accountName : String,
  secret : String,
  issuer : String,
  digits : Number,
  period : Number
}
