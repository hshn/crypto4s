package crypto4s

import java.security.MessageDigest
import java.util

trait Hashed[Alg, A] {
  val hash: Array[Byte]

  def verify(of: A)(using Hashing[Alg], Blob[A]): Boolean = verify(of.hashed[Alg])
  def verify(hashed: Hashed[Alg, A]): Boolean             = verify(hashed.hash)
  def verify(other: Array[Byte]): Boolean                 = MessageDigest.isEqual(hash, other)

  override def equals(obj: Any): Boolean = obj match {
    case other: Hashed[_, _] => util.Arrays.equals(hash, other.hash)
    case _                   => false
  }

  override def hashCode(): Int = util.Arrays.hashCode(hash)
}

object Hashed {
  def apply[Alg, A](hash: Array[Byte]): Hashed[Alg, A] = new Simple(hash)

  private class Simple[Alg, A](val hash: Array[Byte]) extends Hashed[Alg, A]
}
