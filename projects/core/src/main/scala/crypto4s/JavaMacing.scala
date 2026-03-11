package crypto4s

import crypto4s.algorithm.*
import javax.crypto.Mac

abstract class JavaMacing[Alg](algorithmName: String) extends Macing[Alg] {
  override type Result[A] = Maced[Alg, A]

  override def mac[A](key: MacSecretKey[Alg], a: A)(using Blob[A]): Maced[Alg, A] = {
    val m = Mac.getInstance(algorithmName)
    m.init(key.asJava)

    Maced[Alg, A](mac = m.doFinal(a.blob))
  }
}

private[crypto4s] object HmacSHA1JavaMacing   extends JavaMacing[HmacSHA1]("HmacSHA1")
private[crypto4s] object HmacSHA256JavaMacing extends JavaMacing[HmacSHA256]("HmacSHA256")
