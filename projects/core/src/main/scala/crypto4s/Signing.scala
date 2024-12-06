package crypto4s

import crypto4s.implicits.*
import java.security.Signature as JSignature

trait Signing[Alg, KeyAlg] {
  def sign(key: PrivateKey[KeyAlg], data: Array[Byte]): Array[Byte]
  def sign[A: Blob](key: PrivateKey[KeyAlg], a: A): Signed[Alg, A] = Signed(sign(key, a.blob))
}

object Signing {
  given Signing[Algorithm.RS256, Algorithm.RSA] with {
    override def sign(key: PrivateKey[Algorithm.RSA], data: Array[Byte]): Array[Byte] = {
      val verifier = JSignature.getInstance("SHA256withRSA")
      verifier.initSign(key.asJava)
      verifier.update(data)
      verifier.sign()
    }
  }
}
