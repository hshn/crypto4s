package crypto4s

import crypto4s.algorithm.SHA1
import crypto4s.algorithm.SHA256
import java.security.MessageDigest

trait Hashing[Alg, A] { self =>
  type Result <: Hashed[Alg, A]

  def hash(a: A)(using Blob[A]): Result
}

object Hashing {
  given [A]: Hashing[SHA1, A] = new Hashing[SHA1, A] {
    override type Result = Hashed.SHA1[A]
    override def hash(a: A)(using Blob[A]): Hashed.SHA1[A] = {
      val hash = MessageDigest
        .getInstance("SHA-1")
        .digest(a.blob)

      Hashed.SHA1(hash = hash)
    }
  }

  given [A]: Hashing[SHA256, A] = new Hashing[SHA256, A] {
    override type Result = Hashed.SHA256[A]
    override def hash(a: A)(using Blob[A]): Hashed.SHA256[A] = {
      val hash = MessageDigest
        .getInstance("SHA-256")
        .digest(a.blob)

      Hashed.SHA256(hash = hash)
    }
  }
}

object HashingExtension extends HashingExtension
trait HashingExtension {
  extension [A](a: A) {
    def hash[Alg](using hashing: Hashing[Alg, A], blob: Blob[A]): hashing.Result = hashing.hash(a)
  }
}
