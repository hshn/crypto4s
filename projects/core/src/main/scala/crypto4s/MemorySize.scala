package crypto4s

case class MemorySize(bytes: Long) extends AnyVal {
  def toKb: Long = bytes / 1024
  def toMb: Long = toKb / 1024
}

object MemorySize {
  def kb(kb: Int): MemorySize = MemorySize(kb * 1024L)
  def mb(mb: Int): MemorySize = MemorySize(mb * 1024L * 1024L)
}
