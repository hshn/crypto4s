package crypto4s

trait BlobEncoder[-A] { self =>
  def encode(a: A): Blob
  def contraMap[B](f: B => A): BlobEncoder[B] = (b: B) => self.encode(f(b))
}

object BlobEncoder extends BlobEncoderInstances {
  def apply[A](using encoder: BlobEncoder[A]): BlobEncoder[A] = encoder
  def instance[A](f: A => Blob): BlobEncoder[A] = (a: A) => f(a)
}

trait BlobEncoderInstances {
  given BlobEncoder[Blob]                        = BlobEncoder.instance(identity)
  given BlobEncoder[Array[Byte]]                 = BlobEncoder.instance(Blob(_))
  given BlobEncoder[String]                      = BlobEncoder.instance(s => Blob.wrap(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
  given [Alg, A]: BlobEncoder[Hashed[Alg, A]]    = BlobEncoder.instance(_.hash)
  given [Alg, A]: BlobEncoder[Encrypted[Alg, A]] = BlobEncoder.instance(_.blob)
  given [Alg, A]: BlobEncoder[Maced[Alg, A]]     = BlobEncoder.instance(_.mac)
  given [Alg]: BlobEncoder[PrivateKey[Alg]]      = BlobEncoder.instance(k => Blob(k.asJava.getEncoded))
  given [Alg]: BlobEncoder[SecretKey[Alg]]       = BlobEncoder.instance(k => Blob(k.asJava.getEncoded))
  given [Alg]: BlobEncoder[MacKey[Alg]]          = BlobEncoder.instance(k => Blob(k.asJava.getEncoded))
}

object BlobEncoderExtension extends BlobEncoderExtension
trait BlobEncoderExtension {
  extension [A](a: A) {
    def blob(using encoder: BlobEncoder[A]): Blob = encoder.encode(a)
  }
}
