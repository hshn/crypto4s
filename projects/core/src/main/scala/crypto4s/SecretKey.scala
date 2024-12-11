package crypto4s

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey as JSecretKey
import javax.crypto.spec.SecretKeySpec

trait SecretKey[Alg] {
  def encrypt[A: Blob](a: A): Encrypted[Alg, A]
  def decrypt[A: Deserializable](encrypted: Encrypted[Alg, A]): Either[RuntimeException, A]

  def asJava: JSecretKey
}

object SecretKey {
  def AES(size: Int = 256): SecretKey[algorithm.AES] = {
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(size)
    val key = keyGen.generateKey()

    fromJava(key)
  }

  def AES(key: Array[Byte]): Either[IllegalArgumentException, SecretKey[algorithm.AES]] = {
    for {
      keySpec <-
        try {
          Right(new SecretKeySpec(key, "AES"))
        } catch {
          case e: IllegalArgumentException => Left(e)
        }
    } yield {
      fromJava(keySpec)
    }
  }

  def fromJava(key: JSecretKey): SecretKey[algorithm.AES] = JavaSecretKey(
    delegate = key
  )
}

private[crypto4s] case class JavaSecretKey[Alg](
  delegate: JSecretKey
) extends SecretKey[Alg] {

  override def encrypt[A: Blob](a: A): Encrypted[Alg, A] = {
    val cipher = Cipher.getInstance(delegate.getAlgorithm)
    cipher.init(Cipher.ENCRYPT_MODE, delegate)

    Encrypted(cipher.doFinal(a.blob))
  }

  override def decrypt[A: Deserializable](encrypted: Encrypted[Alg, A]): Either[RuntimeException, A] = try {
    val cipher = Cipher.getInstance(delegate.getAlgorithm)
    cipher.init(Cipher.DECRYPT_MODE, delegate)

    cipher.doFinal(encrypted.blob).deserialize[A]
  } catch {
    case e: IllegalBlockSizeException => Left(new RuntimeException("Failed to decrypt", e))
    case e: BadPaddingException       => Left(new RuntimeException("Failed to decrypt", e))
  }

  override def asJava: JSecretKey = delegate
}
