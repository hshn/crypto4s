package crypto4s

import crypto4s.algorithm.HmacSHA1
import crypto4s.algorithm.HmacSHA256
import javax.crypto.SecretKey as JSecretKey
import javax.crypto.spec.SecretKeySpec

trait MacSecretKey[Alg] {
  def asJava: JSecretKey
}

object MacSecretKey {
  def hmacSHA1(key: Array[Byte]): MacSecretKey[HmacSHA1] =
    JavaMacSecretKey(new SecretKeySpec(key, "HmacSHA1"))

  def hmacSHA256(key: Array[Byte]): MacSecretKey[HmacSHA256] =
    JavaMacSecretKey(new SecretKeySpec(key, "HmacSHA256"))
}

private[crypto4s] case class JavaMacSecretKey[Alg](delegate: JSecretKey) extends MacSecretKey[Alg] {
  override def asJava: JSecretKey = delegate
}
