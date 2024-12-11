package crypto4s

import java.security.PublicKey as JPublicKey
import java.security.Signature as JSignature
import javax.crypto.Cipher

trait PublicKey[Alg] { self =>
  def encrypt[A: Blob](a: A): Encrypted[Alg, A]
  def verify[A: Blob, SignAlg](a: A, signature: Signed[SignAlg, A])(using verification: Verification[SignAlg, Alg]): Boolean =
    verification.verify(key = self, a = a, signature = signature)

  def asJava: JPublicKey
}

object PublicKey {
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
