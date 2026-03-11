package crypto4s

import crypto4s.algorithm.HmacSHA1
import crypto4s.algorithm.HmacSHA256
import javax.crypto.SecretKey as JSecretKey
import javax.crypto.spec.SecretKeySpec

trait MacKey[Alg] {
  def asJava: JSecretKey
}

object MacKey {
  def hmacSHA1(key: Array[Byte]): MacKey[HmacSHA1] =
    JavaMacKey(new SecretKeySpec(key, "HmacSHA1"))

  def hmacSHA256(key: Array[Byte]): MacKey[HmacSHA256] =
    JavaMacKey(new SecretKeySpec(key, "HmacSHA256"))
}

private[crypto4s] case class JavaMacKey[Alg](delegate: JSecretKey) extends MacKey[Alg] {
  override def asJava: JSecretKey = delegate
}
