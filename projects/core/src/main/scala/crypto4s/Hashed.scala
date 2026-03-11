package crypto4s

trait Hashed[Alg, A] {
  val hash: Blob

  def verify(of: A)(using Hashing[Alg], BlobEncoder[A]): Boolean = verify(of.hashed[Alg])
  def verify(hashed: Hashed[Alg, A]): Boolean                    = verify(hashed.hash)
  def verify(other: Blob): Boolean                               = hash == other

  override def equals(obj: Any): Boolean = obj match {
    case other: Hashed[_, _] => hash == other.hash
    case _                   => false
  }

  override def hashCode(): Int = hash.hashCode()
}

object Hashed {
  def apply[Alg, A](hash: Array[Byte]): Hashed[Alg, A] = new Simple(Blob.wrap(hash))

  private class Simple[Alg, A](val hash: Blob) extends Hashed[Alg, A]
}
