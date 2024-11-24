package cipher4s

import cipher4s.implicits.*
import java.security.MessageDigest
import java.util.Base64

trait Hashing[Alg, A] { self =>
  type Result <: Hashed[Alg, A]
  def hash(a: A): Result
}

object Hashing {
  given [A](using blob: Blob[A]): Hashing[Algorithm.SHA1, A] = new Hashing[Algorithm.SHA1, A] {
    override type Result = Hashed.SHA1[A]

    override def hash(a: A): Hashed.SHA1[A] = {
      val hash = MessageDigest
        .getInstance("SHA-1")
        .digest(blob.asBlob(a))

      Hashed.SHA1(hash = hash)
    }
  }

  given [A](using blob: Blob[A]): Hashing[Algorithm.SHA256, A] = new Hashing[Algorithm.SHA256, A] {
    override type Result = Hashed.SHA256[A]

    override def hash(a: A): Hashed.SHA256[A] = {
      val hash = MessageDigest
        .getInstance("SHA-256")
        .digest(blob.asBlob(a))

      Hashed.SHA256(hash = hash)
    }
  }
}

trait HashingExtension {
  extension [A](a: A) {
    def toHashed[Alg](using hashing: Hashing[Alg, A], blob: Blob[A]): hashing.Result = hashing.hash(a)
  }
}
