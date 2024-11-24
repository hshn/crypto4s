package cipher4s

import cipher4s.implicits.*
import java.security.PublicKey as JPublicKey
import java.security.Signature as JSignature
import javax.crypto.Cipher

trait PublicKey[Alg] {
  val algorithm: Alg

  def encrypt[A: Blob](a: A): Encrypted[A]
  def verify(data: Array[Byte], signature: Array[Byte]): Boolean
}

private[cipher4s] case class JavaPublicKey[Alg](
  algorithm: Alg,
  delegate: JPublicKey
) extends PublicKey[Alg] {

  override def encrypt[A: Blob](a: A): Encrypted[A] = {
    val cipher = Cipher.getInstance(delegate.getAlgorithm)
    cipher.init(Cipher.ENCRYPT_MODE, delegate)
    Encrypted[A](cipher.doFinal(a.blob))
  }

  override def verify(data: Array[Byte], signature: Array[Byte]): Boolean = {
    val verifier = JSignature.getInstance(delegate.getAlgorithm)
    verifier.initVerify(delegate)
    verifier.update(data)
    verifier.verify(signature)
  }
}
