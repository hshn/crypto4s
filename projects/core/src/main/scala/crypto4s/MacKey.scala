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
  def hmacSHA1(size: Int = 160): MacKey[HmacSHA1]    = generate("HmacSHA1", size)
  def hmacSHA1(key: Array[Byte]): Either[IllegalArgumentException, MacKey[HmacSHA1]] =
    try Right(JavaMacKey(new SecretKeySpec(key, "HmacSHA1")))
    catch { case e: IllegalArgumentException => Left(e) }

  def hmacSHA256(size: Int = 256): MacKey[HmacSHA256] = generate("HmacSHA256", size)
  def hmacSHA256(key: Array[Byte]): Either[IllegalArgumentException, MacKey[HmacSHA256]] =
    try Right(JavaMacKey(new SecretKeySpec(key, "HmacSHA256")))
    catch { case e: IllegalArgumentException => Left(e) }

  private def generate[Alg](algorithm: String, size: Int): MacKey[Alg] = {
    val keyGen = KeyGenerator.getInstance(algorithm)
    keyGen.init(size)
    JavaMacKey(delegate = keyGen.generateKey())
  }
}

private[crypto4s] case class JavaMacKey[Alg](delegate: JSecretKey) extends MacKey[Alg] {
  override def asJava: JSecretKey = delegate
}
