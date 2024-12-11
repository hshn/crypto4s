package crypto4s

import java.security.MessageDigest

trait Hashed[Alg, A] {
  val hash: Array[Byte]

  def verify(of: A)(using Hashing[Alg], Blob[A]): Boolean = verify(of.hashed[Alg])
  def verify(hashed: Hashed[Alg, A]): Boolean             = verify(hashed.hash)
  def verify(other: Array[Byte]): Boolean                 = MessageDigest.isEqual(hash, other)
}

object Hashed {
  def apply[Alg, A](hash: Array[Byte]): Hashed[Alg, A] = new Simple(hash)

  private class Simple[Alg, A](val hash: Array[Byte]) extends Hashed[Alg, A]

}
