package crypto4s

import crypto4s.implicits.*
import java.security.Signature

trait Verification[Alg, KeyAlg] {
  def verify(key: PublicKey[KeyAlg], data: Array[Byte], signature: Array[Byte]): Boolean
  def verify[A: Blob](key: PublicKey[KeyAlg], a: A, signature: Signed[Alg, A]): Boolean = verify(key, a.blob, signature.underlying)
}

object Verification {
  given Verification[Algorithm.RS256, Algorithm.RSA] with {
    override def verify(key: PublicKey[Algorithm.RSA], data: Array[Byte], signature: Array[Byte]): Boolean = {
      val verifier = Signature.getInstance("SHA256withRSA")
      verifier.initVerify(key.asJava)
      verifier.update(data)
      verifier.verify(signature)
    }
  }
}
