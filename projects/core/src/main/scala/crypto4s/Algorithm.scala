package crypto4s

sealed trait Algorithm
object Algorithm {
  type RSA = RSA.type
  case object RSA extends Algorithm

  type AES = AES.type
  case object AES extends Algorithm

  type SHA1 = SHA1.type
  case object SHA1 extends Algorithm

  type SHA256 = SHA256.type
  case object SHA256 extends Algorithm

  type Argon2 = Argon2.type
  case object Argon2 extends Algorithm {
    enum Type {
      case Argon2i, Argon2d, Argon2id
    }
    enum Version {
      case V10, V13
    }
  }

  // signing algorithms
  type RS256 = RS256.type
  case object RS256
}
