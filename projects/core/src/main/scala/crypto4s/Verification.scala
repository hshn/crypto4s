package crypto4s

import crypto4s.algorithm.RS256
import crypto4s.algorithm.RSA
import java.security.Signature

trait Verification[Alg, KeyAlg] {
  def verify(key: PublicKey[KeyAlg], data: Array[Byte], signature: Array[Byte]): Boolean
  def verify[A: Blob](key: PublicKey[KeyAlg], a: A, signature: Signed[Alg, A]): Boolean = verify(key, a.blob, signature.underlying)
}

object Verification {
  given Verification[RS256, RSA] with {
    override def verify(key: PublicKey[RSA], data: Array[Byte], signature: Array[Byte]): Boolean = {
      val verifier = Signature.getInstance("SHA256withRSA")
      verifier.initVerify(key.asJava)
      verifier.update(data)
      verifier.verify(signature)
    }
  }
}
