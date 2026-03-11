package crypto4s

import crypto4s.algorithm.HmacSHA1
import crypto4s.algorithm.HmacSHA256
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey as JSecretKey
import javax.crypto.spec.SecretKeySpec

trait MacKey[Alg] {
  def asJava: JSecretKey
}

object MacKey {
  def hmacSHA1(): MacKey[HmacSHA1]               = fromJava(KeyGenerator.getInstance("HmacSHA1").generateKey())
  def hmacSHA1(key: Array[Byte]): MacKey[HmacSHA1] = JavaMacKey(new SecretKeySpec(key, "HmacSHA1"))

  def hmacSHA256(): MacKey[HmacSHA256]               = fromJava(KeyGenerator.getInstance("HmacSHA256").generateKey())
  def hmacSHA256(key: Array[Byte]): MacKey[HmacSHA256] = JavaMacKey(new SecretKeySpec(key, "HmacSHA256"))

  private def fromJava[Alg](key: JSecretKey): MacKey[Alg] = JavaMacKey(delegate = key)
}

private[crypto4s] case class JavaMacKey[Alg](delegate: JSecretKey) extends MacKey[Alg] {
  override def asJava: JSecretKey = delegate
}
