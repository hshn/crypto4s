package crypto4s

import java.security.PublicKey as JPublicKey
import java.security.Signature as JSignature
import javax.crypto.Cipher

trait PublicKey[Alg] { self =>
  val algorithm: Alg

  def encrypt[A: Blob](a: A): Encrypted[A]
  def verify[A: Blob, SignAlg](a: A, signature: Signed[SignAlg, A])(using verification: Verification[SignAlg, Alg]): Boolean =
    verification.verify(key = self, a = a, signature = signature)

  def asJava: JPublicKey
}

private[crypto4s] case class JavaPublicKey[Alg](
  algorithm: Alg,
  delegate: JPublicKey
) extends PublicKey[Alg] {

  override def encrypt[A: Blob](a: A): Encrypted[A] = {
    val cipher = Cipher.getInstance(delegate.getAlgorithm)
    cipher.init(Cipher.ENCRYPT_MODE, delegate)
    Encrypted[A](cipher.doFinal(a.blob))
  }

  override def asJava: JPublicKey = delegate
}
