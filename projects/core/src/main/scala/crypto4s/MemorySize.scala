package crypto4s

case class MemorySize(bytes: Int) extends AnyVal {
  def toKb: Int = bytes / 1024
  def toMb: Int = toKb / 1024
}

object MemorySize {
  def kb(kb: Int): MemorySize = MemorySize(kb * 1024)
  def mb(mb: Int): MemorySize = kb(mb * 1024)
}
