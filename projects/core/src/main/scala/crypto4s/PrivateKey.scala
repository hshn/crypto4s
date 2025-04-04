package crypto4s

import java.security.KeyFactory
import java.security.PrivateKey as JPrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

sealed trait PrivateKey[Alg] { self =>
  def sign[A: Blob, SignAlg](a: A)(using singing: Signing[SignAlg, Alg]): Signed[SignAlg, A] = singing.sign[A](key = self, a = a)
  def decrypt[A: Deserializable](data: Encrypted[Alg, A]): Either[RuntimeException, A]

  def asJava: JPrivateKey
}

object PrivateKey {
  def RSA(key: Array[Byte]): Either[InvalidKeySpecException, PrivateKey[algorithm.RSA]] = try {
    val keySpec    = new PKCS8EncodedKeySpec(key)
    val keyFactory = KeyFactory.getInstance("RSA")
    val privateKey = keyFactory.generatePrivate(keySpec)

    Right(fromJava(privateKey))
  } catch {
    case e: InvalidKeySpecException => Left(e)
  }

  def fromJava[Alg](key: JPrivateKey): PrivateKey[Alg] = JavaPrivateKey(
    delegate = key
  )
}

private[crypto4s] case class JavaPrivateKey[Alg](
  delegate: JPrivateKey
) extends PrivateKey[Alg] {

  override def decrypt[A: Deserializable](data: Encrypted[Alg, A]): Either[RuntimeException, A] = try {
    val cipher = Cipher.getInstance(delegate.getAlgorithm)
    cipher.init(Cipher.DECRYPT_MODE, delegate)
    cipher.doFinal(data.blob).deserialize[A]
  } catch {
    case e: IllegalBlockSizeException => Left(new RuntimeException("Failed to decrypt", e))
    case e: BadPaddingException       => Left(new RuntimeException("Failed to decrypt", e))
  }

  override def asJava: JPrivateKey = delegate
}
