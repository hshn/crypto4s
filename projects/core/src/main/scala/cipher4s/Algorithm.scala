package cipher4s

sealed trait Algorithm
object Algorithm {
  type RS256 = RS256.type
  case object RS256 extends Algorithm

  type AES256 = AES256.type
  case object AES256 extends Algorithm

  type SHA1 = SHA1.type
  case object SHA1 extends Algorithm

  type SHA256 = SHA256.type
  case object SHA256 extends Algorithm
}
