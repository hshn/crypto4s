package crypto4s

import crypto4s.Hashed
import crypto4s.algorithm.*
import java.security.MessageDigest

abstract class MessageDigestHashing[Alg](algorithmName: String) extends Hashing[Alg] {
  override type Result[A] = Hashed[Alg, A]

  override def hash[A](a: A)(using Blob[A]): Hashed[Alg, A] = {
    val hash = MessageDigest
      .getInstance(algorithmName)
      .digest(a.blob)

    Hashed[Alg, A](hash = hash)
  }
}

private[crypto4s] object SHA1MessageDigestHashing   extends MessageDigestHashing[SHA1]("SHA-1")
private[crypto4s] object SHA256MessageDigestHashing extends MessageDigestHashing[SHA256]("SHA-256")
