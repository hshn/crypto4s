package crypto4s.algorithm

type Argon2 = Argon2.type
case object Argon2 {
  enum Type {
    case Argon2i, Argon2d, Argon2id
  }
  enum Version {
    case V10, V13
  }
}
