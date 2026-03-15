package crypto4s

import crypto4s.algorithm.AES
import crypto4s.algorithm.RSA
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.GCMParameterSpec

trait Decrypting[Alg, Key] {
  def decrypt(key: Key, data: Array[Byte]): Either[RuntimeException, Array[Byte]]
  def decrypt[A](key: Key, encrypted: Encrypted[Alg, A])(using deserializable: Deserializable[A]): Either[RuntimeException, A] =
    decrypt(key, encrypted.blob.toByteArray).flatMap(deserializable.deserialize)
}

object Decrypting {
  given Decrypting[AES, SecretKey[AES]] with {
    override def decrypt(key: SecretKey[AES], data: Array[Byte]): Either[RuntimeException, Array[Byte]] = {
      val minLength = AES.ivLength + AES.tagLength / 8
      if (data.length < minLength)
        Left(new RuntimeException("Failed to decrypt"))
      else try {
        val iv = data.take(AES.ivLength)
        val ciphertext = data.drop(AES.ivLength)
        val cipher = Cipher.getInstance(AES.transformation)
        cipher.init(Cipher.DECRYPT_MODE, key.asJava, new GCMParameterSpec(AES.tagLength, iv))
        Right(cipher.doFinal(ciphertext))
      } catch {
        case e: AEADBadTagException       => Left(new RuntimeException("Failed to decrypt", e))
        case e: IllegalBlockSizeException => Left(new RuntimeException("Failed to decrypt", e))
      }
    }
  }

  given Decrypting[RSA, PrivateKey[RSA]] with {
    override def decrypt(key: PrivateKey[RSA], data: Array[Byte]): Either[RuntimeException, Array[Byte]] = try {
      val cipher = Cipher.getInstance(RSA.transformation)
      cipher.init(Cipher.DECRYPT_MODE, key.asJava)
      Right(cipher.doFinal(data))
    } catch {
      case e: IllegalBlockSizeException => Left(new RuntimeException("Failed to decrypt", e))
      case e: BadPaddingException       => Left(new RuntimeException("Failed to decrypt", e))
    }
  }
}
