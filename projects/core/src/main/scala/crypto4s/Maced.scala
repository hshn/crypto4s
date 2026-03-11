package crypto4s

import java.security.MessageDigest
import java.util

trait Maced[Alg, A] {
  val mac: Array[Byte]

  def verify(other: Maced[Alg, A]): Boolean = verify(other.mac)
  def verify(other: Array[Byte]): Boolean    = MessageDigest.isEqual(mac, other)

  override def equals(obj: Any): Boolean = obj match {
    case other: Maced[_, _] => util.Arrays.equals(mac, other.mac)
    case _                  => false
  }

  override def hashCode(): Int = util.Arrays.hashCode(mac)
}

object Maced {
  def apply[Alg, A](mac: Array[Byte]): Maced[Alg, A] = new Simple(mac)

  private class Simple[Alg, A](val mac: Array[Byte]) extends Maced[Alg, A]
}
