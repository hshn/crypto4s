package crypto4s

import crypto4s.algorithm.AES
import crypto4s.algorithm.RSA
import javax.crypto.Cipher

trait Encrypting[Alg, Key] {
  def encrypt(key: Key, data: Array[Byte]): Array[Byte]
  def encrypt[A](key: Key, a: A)(using encoder: BlobEncoder[A]): Encrypted[Alg, A] =
    Encrypted(Blob.wrap(encrypt(key, encoder.encode(a).toByteArray)))
}

object Encrypting {
  given Encrypting[AES, SecretKey[AES]] with {
    override def encrypt(key: SecretKey[AES], data: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance(key.asJava.getAlgorithm)
      cipher.init(Cipher.ENCRYPT_MODE, key.asJava)
      cipher.doFinal(data)
    }
  }

  given Encrypting[RSA, PublicKey[RSA]] with {
    override def encrypt(key: PublicKey[RSA], data: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
      cipher.init(Cipher.ENCRYPT_MODE, key.asJava)
      cipher.doFinal(data)
    }
  }
}
