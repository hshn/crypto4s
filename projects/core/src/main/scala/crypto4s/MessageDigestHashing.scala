package crypto4s

import crypto4s.Hashed
import crypto4s.algorithm.*
import java.security.MessageDigest

abstract class MessageDigestHashing[Alg, A](algorithmName: String) extends Hashing[Alg, A] {
  override type Result = Hashed[Alg, A]

  override def hash(a: A)(using Blob[A]): Hashed[Alg, A] = {
    val hash = MessageDigest
      .getInstance(algorithmName)
      .digest(a.blob)

    Hashed(hash = hash)
  }
}

private[crypto4s] class SHA1MessageDigestHashing[A]   extends MessageDigestHashing[SHA1, A]("SHA-1")
private[crypto4s] class SHA256MessageDigestHashing[A] extends MessageDigestHashing[SHA256, A]("SHA-256")
