package crypto4s

import java.security.MessageDigest
import java.util.Base64

final class Blob private[crypto4s] (private val bytes: Array[Byte]) {
  def length: Int              = bytes.length
  def toByteArray: Array[Byte] = bytes.clone()
  def toHexString: String      = bytes.map(b => "%02x".format(b & 0xff)).mkString
  def toBase64: Blob           = Blob.wrap(Base64.getEncoder.encode(bytes))
  def toUrlBase64: Blob        = Blob.wrap(Base64.getUrlEncoder.withoutPadding.encode(bytes))
  def toUtf8String: String     = new String(bytes, java.nio.charset.StandardCharsets.UTF_8)

  override def equals(obj: Any): Boolean = obj match {
    case other: Blob => MessageDigest.isEqual(bytes, other.bytes)
    case _           => false
  }

  override def hashCode(): Int  = java.util.Arrays.hashCode(bytes)
  override def toString: String = toHexString
}

object Blob {
  def apply(bytes: Array[Byte]): Blob                  = new Blob(bytes.clone())
  private[crypto4s] def wrap(bytes: Array[Byte]): Blob = new Blob(bytes)
}
