package crypto4s.algorithm

object RSA {
  type ECB = ECB.type
  case object ECB {
    val transformation: String = "RSA/ECB/PKCS1Padding"
  }
}
type RSA = RSA.ECB

type AES = AES.type
case object AES

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
