package crypto4s

import crypto4s.algorithm.SHA1
import crypto4s.algorithm.SHA256
import java.security.MessageDigest
import java.util

trait Hashed[Alg, A] {
  val hash: Array[Byte]

  def verify(of: A)(using Hashing[Alg, A], Blob[A]): Boolean = verify(of.hash[Alg])
  def verify(hashed: Hashed[Alg, A]): Boolean                = verify(hashed.hash)
  def verify(other: Array[Byte]): Boolean                    = MessageDigest.isEqual(hash, other)

  def toHexString: String       = hash.map("%02x".format(_)).mkString
  def toBase64String: String    = util.Base64.getEncoder.encodeToString(hash)
  def toUrlBase64String: String = util.Base64.getUrlEncoder.withoutPadding().encodeToString(hash)
}

object Hashed {
  case class SHA1[A](hash: Array[Byte])   extends Hashed[algorithm.SHA1, A]
  case class SHA256[A](hash: Array[Byte]) extends Hashed[algorithm.SHA256, A]
}
