package crypto4s

import crypto4s.algorithm.AES
import crypto4s.algorithm.RSA

trait Deserializable[A] {
  def deserialize(a: Array[Byte]): Either[DeserializationException, A]
}

object Deserializable {
  given Deserializable[Array[Byte]] with {
    override def deserialize(a: Array[Byte]): Either[DeserializationException, Array[Byte]] = Right(a)
  }
  given Deserializable[String] with {
    override def deserialize(a: Array[Byte]): Either[DeserializationException, String] = Right(new String(a))
  }
  given Deserializable[PrivateKey[RSA]] with {
    override def deserialize(a: Array[Byte]): Either[DeserializationException, PrivateKey[RSA]] =
      PrivateKey.RSA(a).left.map(e => new DeserializationException.InvalidKeyBytes("RSA private key", e))
  }
  given Deserializable[SecretKey[AES]] with {
    override def deserialize(a: Array[Byte]): Either[DeserializationException, SecretKey[AES]] =
      SecretKey.AES(a).left.map(e => new DeserializationException.InvalidKeyBytes("AES secret key", e))
  }
}

object DeserializableExtension extends DeserializableExtension
trait DeserializableExtension {
  extension (a: Array[Byte]) {
    def deserialize[A](using deserializable: Deserializable[A]): Either[DeserializationException, A] = deserializable.deserialize(a)
  }
}
