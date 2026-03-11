package crypto4s

trait Maced[Alg, A] {
  val mac: Blob

  def verify(other: Maced[Alg, A]): Boolean = verify(other.mac)
  def verify(other: Blob): Boolean          = mac == other

  override def equals(obj: Any): Boolean = obj match {
    case other: Maced[_, _] => mac == other.mac
    case _                  => false
  }

  override def hashCode(): Int = mac.hashCode()
}

object Maced {
  def apply[Alg, A](mac: Array[Byte]): Maced[Alg, A] = new Simple(Blob.wrap(mac))

  private class Simple[Alg, A](val mac: Blob) extends Maced[Alg, A]
}
