package cipher4s

import cipher4s.Algorithm.RS256

trait Deserializable[A] {
  def deserialize(a: Array[Byte]): Either[RuntimeException, A]
}

object Deserializable {
  given Deserializable[Array[Byte]] with {
    override def deserialize(a: Array[Byte]): Either[RuntimeException, Array[Byte]] = Right(a)
  }
  given Deserializable[String] with {
    override def deserialize(a: Array[Byte]): Either[RuntimeException, String] = Right(new String(a))
  }
  given Deserializable[PrivateKey[Algorithm.RS256]] with {
    override def deserialize(a: Array[Byte]): Either[RuntimeException, PrivateKey[RS256]] =
      PrivateKey.rs256(a).left.map(e => new RuntimeException("Failed to deserialize private key", e))
  }
  given Deserializable[SecretKey[Algorithm.AES256]] with {
    override def deserialize(a: Array[Byte]): Either[RuntimeException, SecretKey[Algorithm.AES256]] =
      SecretKey.aes256(a).left.map(e => new RuntimeException("Failed to deserialize secret key", e))
  }
}

trait DeserializableExtension {
  extension (a: Array[Byte]) {
    def deserialize[A](using deserializable: Deserializable[A]): Either[RuntimeException, A] = deserializable.deserialize(a)
  }
}
