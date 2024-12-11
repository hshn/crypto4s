package crypto4s

trait Blob[A] { self =>
  def asBlob(a: A): Array[Byte]

  def contraMap[B](f: B => A): Blob[B] = new Blob[B] {
    override def asBlob(b: B): Array[Byte] = self.asBlob(f(b))
  }
}

object Blob extends BlobInstances {
  def apply[A](using blob: Blob[A]): Blob[A] = blob
  def instance[A](f: A => Array[Byte]): Blob[A] = new Blob[A] {
    override def asBlob(a: A): Array[Byte] = f(a)
  }
}

trait BlobInstances {
  given Blob[Array[Byte]]                 = Blob.instance(identity)
  given Blob[String]                      = Blob.instance(_.getBytes)
  given [Alg, A]: Blob[Hashed[Alg, A]]    = Blob.instance(_.hash)
  given [Alg, A]: Blob[Encrypted[Alg, A]] = Blob.instance(_.blob)
  given [Alg]: Blob[PrivateKey[Alg]]      = Blob.instance(_.asJava.getEncoded)
  given [Alg]: Blob[SecretKey[Alg]]       = Blob.instance(_.asJava.getEncoded)
}

object BlobExtension extends BlobExtension
trait BlobExtension {
  extension [A](a: A) {
    def blob(using blob: Blob[A]): Array[Byte] = blob.asBlob(a)
  }
}
