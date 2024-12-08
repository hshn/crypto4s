package crypto4s

import crypto4s.algorithm.{AES, RSA}

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
  given Deserializable[PrivateKey[RSA]] with {
    override def deserialize(a: Array[Byte]): Either[RuntimeException, PrivateKey[RSA]] =
      PrivateKey.RSA(a).left.map(e => new RuntimeException("Failed to deserialize private key", e))
  }
  given Deserializable[SecretKey[AES]] with {
    override def deserialize(a: Array[Byte]): Either[RuntimeException, SecretKey[AES]] =
      SecretKey.AES(a).left.map(e => new RuntimeException("Failed to deserialize secret key", e))
  }
}

object DeserializableExtension extends DeserializableExtension
trait DeserializableExtension {
  extension (a: Array[Byte]) {
    def deserialize[A](using deserializable: Deserializable[A]): Either[RuntimeException, A] = deserializable.deserialize(a)
  }
}
