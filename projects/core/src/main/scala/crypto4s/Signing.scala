package crypto4s

import crypto4s.algorithm.RS256
import crypto4s.algorithm.RSA
import java.security.Signature as JSignature

trait Signing[Alg, KeyAlg] {
  def sign(key: PrivateKey[KeyAlg], data: Array[Byte]): Array[Byte]
  def sign[A: Blob](key: PrivateKey[KeyAlg], a: A): Signed[Alg, A] = Signed(sign(key, a.blob))

  def asJava: JSignature
}

object Signing {
  given Signing[RS256, RSA] = new JavaSigning(JSignature.getInstance("SHA256withRSA"))
}

private[crypto4s] class JavaSigning[Alg, KeyAlg](
  delegate: JSignature
) extends Signing[Alg, KeyAlg] {
  override def sign(key: PrivateKey[KeyAlg], data: Array[Byte]): Array[Byte] = {
    delegate.initSign(key.asJava)
    delegate.update(data)
    delegate.sign()
  }

  override val asJava: JSignature = delegate
}
