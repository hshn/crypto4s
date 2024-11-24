package cipher4s

import cipher4s.implicits.*
import java.security.KeyFactory
import java.security.PrivateKey as JPrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

sealed trait PrivateKey[Alg] {
  val algorithm: Alg

  def sign(data: Array[Byte]): Array[Byte]
  def decrypt[A: Deserializable](data: Encrypted[A]): Either[RuntimeException, A]

  def asJava: JPrivateKey
}

object PrivateKey {
  def rs256(key: Array[Byte]): Either[InvalidKeySpecException, PrivateKey[Algorithm.RS256]] = try {
    val keySpec    = new PKCS8EncodedKeySpec(key)
    val keyFactory = KeyFactory.getInstance("RSA")
    val privateKey = keyFactory.generatePrivate(keySpec)

    Right(
      JavaPrivateKey(
        algorithm = Algorithm.RS256,
        delegate = privateKey
      )
    )
  } catch {
    case e: InvalidKeySpecException => Left(e)
  }
}

private[cipher4s] case class JavaPrivateKey[Alg](
  algorithm: Alg,
  delegate: JPrivateKey
) extends PrivateKey[Alg] {
  override def sign(data: Array[Byte]): Array[Byte] = {
    val signer = Cipher.getInstance(delegate.getAlgorithm)
    signer.init(Cipher.ENCRYPT_MODE, delegate)
    signer.doFinal(data)
  }

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
