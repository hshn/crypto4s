package crypto4s

import java.security.KeyFactory
import java.security.PrivateKey as JPrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec

sealed trait PrivateKey[Alg] { self =>
  def decrypt[A: Deserializable](encrypted: Encrypted[Alg, A])(using decrypting: Decrypting[Alg, PrivateKey[Alg]]): Either[RuntimeException, A] =
    decrypting.decrypt(self, encrypted)
  def sign[A: BlobEncoder, SignAlg](a: A)(using singing: Signing[SignAlg, Alg]): Signed[SignAlg, A] = singing.sign[A](key = self, a = a)

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

  override def asJava: JPrivateKey = delegate
}
