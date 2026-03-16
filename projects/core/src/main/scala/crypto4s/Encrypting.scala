package crypto4s

import crypto4s.algorithm.AES
import crypto4s.algorithm.RSA
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

trait Encrypting[Alg, Key] {
  def encrypt(key: Key, data: Array[Byte]): Array[Byte]
  def encrypt[A](key: Key, a: A)(using encoder: BlobEncoder[A]): Encrypted[Alg, A] =
    Encrypted(Blob.wrap(encrypt(key, encoder.encode(a).toByteArray)))
}

object Encrypting {
  given Encrypting[AES, SecretKey[AES]] with {
    override def encrypt(key: SecretKey[AES], data: Array[Byte]): Array[Byte] = {
      val iv = new Array[Byte](AES.ivLength)
      new SecureRandom().nextBytes(iv)
      val cipher = Cipher.getInstance(AES.transformation)
      cipher.init(Cipher.ENCRYPT_MODE, key.asJava, new GCMParameterSpec(AES.tagLength, iv))
      val ciphertext = cipher.doFinal(data)
      iv ++ ciphertext
    }
  }

  given Encrypting[RSA, PublicKey[RSA]] with {
    override def encrypt(key: PublicKey[RSA], data: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance(RSA.transformation)
      cipher.init(Cipher.ENCRYPT_MODE, key.asJava)
      cipher.doFinal(data)
    }
  }
}
