package cipher4s

import java.util

case class Encrypted[A](blob: Array[Byte]) extends AnyVal {
  override def equals(obj: Any): Boolean = obj match {
    case Encrypted(otherBlob) => blob.sameElements(otherBlob)
    case _                    => false
  }

  override def hashCode(): Int = util.Arrays.hashCode(blob)
}
