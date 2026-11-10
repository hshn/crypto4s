package crypto4s

import crypto4s.algorithm.AES
import crypto4s.algorithm.AESGCM
import crypto4s.algorithm.RSA
import crypto4s.algorithm.RSAOAEP256
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.GCMParameterSpec

trait Decrypting[Alg, Key] {

  /** Decrypts `data` that was encrypted bound to `context`. Fails when the context differs from the one used to encrypt. An empty context
    * is the same as no context.
    */
  def decrypt(key: Key, data: Array[Byte], context: Array[Byte]): Either[RuntimeException, Array[Byte]]
  def decrypt(key: Key, data: Array[Byte]): Either[RuntimeException, Array[Byte]] = decrypt(key, data, Array.emptyByteArray)
  def decrypt[A, C](key: Key, encrypted: Encrypted[Alg, A], context: C)(using
    deserializable: Deserializable[A],
    contextEncoder: BlobEncoder[C]
  ): Either[RuntimeException, A] =
    decrypt(key, encrypted.blob.toByteArray, contextEncoder.encode(context).toByteArray).flatMap(deserializable.deserialize)
  def decrypt[A](key: Key, encrypted: Encrypted[Alg, A])(using deserializable: Deserializable[A]): Either[RuntimeException, A] =
    decrypt(key, encrypted.blob.toByteArray).flatMap(deserializable.deserialize)
}

object Decrypting {
  given Decrypting[AESGCM, SecretKey[AES]] with {
    override def decrypt(key: SecretKey[AES], data: Array[Byte], context: Array[Byte]): Either[RuntimeException, Array[Byte]] = {
      val minLength = AESGCM.ivLength + AESGCM.tagLength / 8
      if (data.length < minLength)
        Left(new RuntimeException("Failed to decrypt"))
      else
        try {
          val iv         = data.take(AESGCM.ivLength)
          val ciphertext = data.drop(AESGCM.ivLength)
          val cipher     = Cipher.getInstance(AESGCM.transformation)
          cipher.init(Cipher.DECRYPT_MODE, key.asJava, new GCMParameterSpec(AESGCM.tagLength, iv))
          cipher.updateAAD(context)
          Right(cipher.doFinal(ciphertext))
        } catch {
          case e: BadPaddingException       => Left(new RuntimeException("Failed to decrypt", e))
          case e: IllegalBlockSizeException => Left(new RuntimeException("Failed to decrypt", e))
        }
    }
  }

  given Decrypting[RSAOAEP256, PrivateKey[RSA]] with {
    override def decrypt(key: PrivateKey[RSA], data: Array[Byte], context: Array[Byte]): Either[RuntimeException, Array[Byte]] = try {
      val cipher = Cipher.getInstance(RSAOAEP256.transformation)
      cipher.init(Cipher.DECRYPT_MODE, key.asJava, RSAOAEP256.oaepParameters(label = context))
      Right(cipher.doFinal(data))
    } catch {
      case e: IllegalBlockSizeException => Left(new RuntimeException("Failed to decrypt", e))
      case e: BadPaddingException       => Left(new RuntimeException("Failed to decrypt", e))
    }
  }
}
