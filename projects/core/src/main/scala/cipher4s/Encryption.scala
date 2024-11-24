package cipher4s

trait Encryption[Key] {
  def encrypt(key: Key, data: Array[Byte]): Array[Byte]
}
