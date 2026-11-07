package crypto4s

trait Hashed[Alg, A] {
  val hash: Blob

  def verify(of: A)(using BlobEncoder[A]): Boolean
  def verify(hashed: Hashed[Alg, A]): Boolean = verify(hashed.hash)
  def verify(other: Blob): Boolean            = hash == other

  override def equals(obj: Any): Boolean = obj match {
    case other: Hashed[_, _] => hash == other.hash
    case _                   => false
  }

  override def hashCode(): Int = hash.hashCode()
}

object Hashed {
  def apply[Alg, A](hash: Array[Byte])(using hashing: Hashing[Alg]): Hashed[Alg, A] = new Simple(Blob.wrap(hash), hashing)

  private class Simple[Alg, A](val hash: Blob, hashing: Hashing[Alg]) extends Hashed[Alg, A] {
    override def verify(of: A)(using BlobEncoder[A]): Boolean = verify(hashing.hash(of))
  }
}
