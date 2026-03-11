package crypto4s

import crypto4s.algorithm.RS256
import crypto4s.algorithm.RSA
import java.security.Signature as JSignature

trait Signing[Alg, KeyAlg] {
  def sign(key: PrivateKey[KeyAlg], data: Array[Byte]): Array[Byte]
  def sign[A: BlobEncoder](key: PrivateKey[KeyAlg], a: A): Signed[Alg, A] = Signed(Blob.wrap(sign(key, a.blob.toByteArray)))
}

object Signing {
  given Signing[RS256, RSA] with {
    override def sign(key: PrivateKey[RSA], data: Array[Byte]): Array[Byte] = {
      val verifier = JSignature.getInstance("SHA256withRSA")
      verifier.initSign(key.asJava)
      verifier.update(data)
      verifier.sign()
    }
  }
}
