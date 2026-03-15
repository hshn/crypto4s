package crypto4s.algorithm

type RSA = RSA.type
case object RSA {
  val transformation: String = "RSA/ECB/PKCS1Padding"
}

type AES = AES.type
case object AES {
  val transformation: String = "AES/GCM/NoPadding"
  val ivLength: Int          = 12
  val tagLength: Int         = 128
}

type SHA1 = SHA1.type
case object SHA1

type SHA256 = SHA256.type
case object SHA256

// signing algorithms
type RS256 = RS256.type
case object RS256

// mac algorithms
type HmacSHA1 = HmacSHA1.type
case object HmacSHA1

type HmacSHA256 = HmacSHA256.type
case object HmacSHA256
