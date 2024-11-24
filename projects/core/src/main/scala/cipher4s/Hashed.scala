package cipher4s

import cipher4s.implicits.*
import java.security.MessageDigest
import java.util
import java.util.Arrays
import java.util.Base64

trait Hashed[Alg, A] {
  val hash: Array[Byte]

  def hasSameHash(of: A)(using Hashing[Alg, A], Blob[A]): Boolean = {
    val hashed = of.toHashed[Alg]

    isEqualTo(hashed.hash)
  }

  def isEqualTo(other: Array[Byte]): Boolean = MessageDigest.isEqual(hash, other)

  def toHexString: String       = hash.map("%02x".format(_)).mkString
  def toBase64String: String    = Base64.getEncoder.encodeToString(hash)
  def toUrlBase64String: String = Base64.getUrlEncoder.withoutPadding().encodeToString(hash)
}

object Hashed {
  case class SHA1[A](hash: Array[Byte]) extends Hashed[Algorithm.SHA1, A] {
    override def equals(obj: Any): Boolean = obj match {
      case SHA1(hash) => MessageDigest.isEqual(this.hash, hash)
      case _          => false
    }
    override def hashCode(): Int = util.Arrays.hashCode(hash)
  }
  case class SHA256[A](hash: Array[Byte]) extends Hashed[Algorithm.SHA256, A] {
    override def equals(obj: Any): Boolean = obj match {
      case SHA256(hash) => MessageDigest.isEqual(this.hash, hash)
      case _            => false
    }
    override def hashCode(): Int = util.Arrays.hashCode(hash)
  }
}
