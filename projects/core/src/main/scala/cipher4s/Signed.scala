package cipher4s

case class Signed[Alg, A](underlying: Array[Byte]) extends AnyVal
