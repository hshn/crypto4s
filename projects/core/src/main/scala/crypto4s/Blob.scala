package crypto4s

trait Blob[A] {
  def asBlob(a: A): Array[Byte]
}

object Blob extends BlobInstances

trait BlobInstances {
  given Blob[Array[Byte]] with {
    override def asBlob(a: Array[Byte]): Array[Byte] = a
  }
  given Blob[String] with {
    override def asBlob(a: String): Array[Byte] = a.getBytes
  }
  given [Alg, A]: Blob[Hashed[Alg, A]] with {
    override def asBlob(a: Hashed[Alg, A]): Array[Byte] = a.hash
  }
  given [A]: Blob[Encrypted[A]] with {
    override def asBlob(a: Encrypted[A]): Array[Byte] = a.blob
  }
  given [Alg]: Blob[PrivateKey[Alg]] with {
    override def asBlob(a: PrivateKey[Alg]): Array[Byte] = a.asJava.getEncoded
  }
  given [Alg]: Blob[SecretKey[Alg]] with {
    override def asBlob(a: SecretKey[Alg]): Array[Byte] = a.asJava.getEncoded
  }
}

trait BlobExtension {
  extension [A](a: A) {
    def blob(using blob: Blob[A]): Array[Byte] = blob.asBlob(a)
  }
}
