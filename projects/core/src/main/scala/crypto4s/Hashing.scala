package crypto4s

import crypto4s.algorithm.SHA1
import crypto4s.algorithm.SHA256

trait Hashing[Alg] { self =>
  type Result[A] <: Hashed[Alg, A]

  def hash[A](a: A)(using Blob[A]): Result[A]
}

object Hashing {
  def apply[Alg](using hashing: Hashing[Alg]): Hashing[Alg] = hashing

  given [A]: Hashing[SHA1]   = SHA1MessageDigestHashing
  given [A]: Hashing[SHA256] = SHA256MessageDigestHashing
}

object HashingExtension extends HashingExtension
trait HashingExtension {
  extension [A](a: A) {
    def hashed[Alg](using hashing: Hashing[Alg], blob: Blob[A]): hashing.Result[A] = hashing.hash(a)
  }
}
