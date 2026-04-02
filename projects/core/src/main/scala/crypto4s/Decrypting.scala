package crypto4s

import crypto4s.algorithm.AES
import crypto4s.algorithm.RSA
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.GCMParameterSpec

trait Decrypting[Alg, Key] {
  def decrypt(key: Key, data: Array[Byte]): Either[DecryptionException, Array[Byte]]
  def decrypt[A](key: Key, encrypted: Encrypted[Alg, A])(using
    deserializable: Deserializable[A]
  ): Either[DecryptionException | DeserializationException, A] =
    decrypt(key, encrypted.blob.toByteArray) match {
      case Left(e)      => Left(e)
      case Right(bytes) => deserializable.deserialize(bytes)
    }
}

object Decrypting {
  given Decrypting[AES, SecretKey[AES]] with {
    override def decrypt(key: SecretKey[AES], data: Array[Byte]): Either[DecryptionException, Array[Byte]] = {
      val minLength = AES.ivLength + AES.tagLength / 8
      if (data.length < minLength)
        Left(new DecryptionException.InvalidCiphertext(s"Ciphertext too short: ${data.length} bytes, minimum $minLength"))
      else
        try {
          val iv         = data.take(AES.ivLength)
          val ciphertext = data.drop(AES.ivLength)
          val cipher     = Cipher.getInstance(AES.transformation)
          cipher.init(Cipher.DECRYPT_MODE, key.asJava, new GCMParameterSpec(AES.tagLength, iv))
          Right(cipher.doFinal(ciphertext))
        } catch {
          case e: AEADBadTagException       => Left(new DecryptionException.IntegrityCheckFailed(e))
          case e: IllegalBlockSizeException => Left(new DecryptionException.InvalidCiphertext("Invalid ciphertext block size", e))
        }
    }
  }

  given Decrypting[RSA, PrivateKey[RSA]] with {
    override def decrypt(key: PrivateKey[RSA], data: Array[Byte]): Either[DecryptionException, Array[Byte]] = try {
      val cipher = Cipher.getInstance(RSA.transformation)
      cipher.init(Cipher.DECRYPT_MODE, key.asJava)
      Right(cipher.doFinal(data))
    } catch {
      case e: IllegalBlockSizeException => Left(new DecryptionException.InvalidCiphertext("Invalid ciphertext block size", e))
      case e: BadPaddingException       => Left(new DecryptionException.IntegrityCheckFailed(e))
    }
  }
}
