package crypto4s

import crypto4s.algorithm.SHA1
import crypto4s.algorithm.SHA256
import java.security.MessageDigest

trait Hashing[Alg, A] { self =>
  type Result <: Hashed[Alg, A]

  def hash(a: A)(using Blob[A]): Result
}

object Hashing {
  given [A]: Hashing[SHA1, A]   = new SHA1MessageDigestHashing[A]
  given [A]: Hashing[SHA256, A] = new SHA256MessageDigestHashing[A]
}

object HashingExtension extends HashingExtension
trait HashingExtension {
  extension [A](a: A) {
    def hash[Alg](using hashing: Hashing[Alg, A], blob: Blob[A]): hashing.Result = hashing.hash(a)
  }
}
