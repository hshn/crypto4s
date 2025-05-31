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
  given Signing[RS256, RSA] = new JavaSigning("SHA256withRSA")
}

private[crypto4s] class JavaSigning[Alg, KeyAlg](
  algorithm: String
) extends Signing[Alg, KeyAlg] {
  override def sign(key: PrivateKey[KeyAlg], data: Array[Byte]): Array[Byte] = {
    val signature = JSignature.getInstance(algorithm)

    signature.initSign(key.asJava)
    signature.update(data)
    signature.sign()
  }

  override def asJava: JSignature = JSignature.getInstance(algorithm)
}
