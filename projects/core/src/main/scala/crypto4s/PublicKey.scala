package crypto4s

import java.security.KeyFactory
import java.security.PublicKey as JPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

trait PublicKey[Alg] { self =>
  def encrypt[A: Blob](a: A): Encrypted[Alg, A]
  def verify[A: Blob, SignAlg](a: A, signature: Signed[SignAlg, A])(using verification: Verification[SignAlg, Alg]): Boolean =
    verification.verify(key = self, a = a, signature = signature)

  def asJava: JPublicKey
}

object PublicKey {
  def RSA(key: Array[Byte]): Either[InvalidKeySpecException, PublicKey[algorithm.RSA]] = try {
    val keySpec    = new X509EncodedKeySpec(key)
    val keyFactory = KeyFactory.getInstance("RSA")
    val publicKey  = keyFactory.generatePublic(keySpec)

    Right(fromJava(publicKey))
  } catch {
    case e: InvalidKeySpecException => Left(e)
  }

  def fromJava[Alg](key: JPublicKey): PublicKey[Alg] = JavaPublicKey(
    delegate = key
  )
}

private[crypto4s] case class JavaPublicKey[Alg](
  delegate: JPublicKey
) extends PublicKey[Alg] {

  override def encrypt[A: Blob](a: A): Encrypted[Alg, A] = {
    val cipher = Cipher.getInstance(delegate.getAlgorithm)
    cipher.init(Cipher.ENCRYPT_MODE, delegate)
    Encrypted(cipher.doFinal(a.blob))
  }

  override def asJava: JPublicKey = delegate
}
