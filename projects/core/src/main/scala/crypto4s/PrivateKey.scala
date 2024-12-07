package crypto4s

import crypto4s.algorithm.RSA
import java.security.KeyFactory
import java.security.PrivateKey as JPrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

sealed trait PrivateKey[Alg] { self =>
  type Algorithm = Alg
  val algorithm: Alg

  def sign[A: Blob, SignAlg](a: A)(using singing: Signing[SignAlg, Alg]): Signed[SignAlg, A] = singing.sign[A](key = self, a = a)
  def decrypt[A: Deserializable](data: Encrypted[A]): Either[RuntimeException, A]

  def asJava: JPrivateKey
}

object PrivateKey {
  def RSA(key: Array[Byte]): Either[InvalidKeySpecException, PrivateKey[algorithm.RSA]] = try {
    val keySpec    = new PKCS8EncodedKeySpec(key)
    val keyFactory = KeyFactory.getInstance("RSA")
    val privateKey = keyFactory.generatePrivate(keySpec)

    Right(
      JavaPrivateKey(
        algorithm = algorithm.RSA,
        delegate = privateKey
      )
    )
  } catch {
    case e: InvalidKeySpecException => Left(e)
  }
}

private[crypto4s] case class JavaPrivateKey[Alg](
  algorithm: Alg,
  delegate: JPrivateKey
) extends PrivateKey[Alg] {

  override def decrypt[A: Deserializable](data: Encrypted[A]): Either[RuntimeException, A] = try {
    val decrypter = Cipher.getInstance(delegate.getAlgorithm)
    decrypter.init(Cipher.DECRYPT_MODE, delegate)
    decrypter.doFinal(data.blob).deserialize[A]
  } catch {
    case e: IllegalBlockSizeException => Left(new RuntimeException("Failed to decrypt", e))
    case e: BadPaddingException       => Left(new RuntimeException("Failed to decrypt", e))
  }

  override def asJava: JPrivateKey = delegate
}
