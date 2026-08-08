package crypto4s

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey as JSecretKey
import javax.crypto.spec.SecretKeySpec

trait SecretKey[Alg] { self =>
  def encrypt[A: BlobEncoder](a: A)(using encrypting: Encrypting[Alg, SecretKey[Alg]]): Encrypted[Alg, A] =
    encrypting.encrypt(self, a)
  def decrypt[A: Deserializable](encrypted: Encrypted[Alg, A])(using
    decrypting: Decrypting[Alg, SecretKey[Alg]]
  ): Either[DecryptionException | DeserializationException, A] =
    decrypting.decrypt(self, encrypted)

  def asJava: JSecretKey
}

object SecretKey {
  private val validAESKeyLengths = Set(16, 24, 32)

  def AES(size: Int = 256): SecretKey[algorithm.AES] = {
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(size)
    val key = keyGen.generateKey()

    fromJava(key)
  }

  def AES(key: Array[Byte]): Either[IllegalArgumentException, SecretKey[algorithm.AES]] = {
    if (!validAESKeyLengths.contains(key.length))
      Left(new IllegalArgumentException(s"Invalid AES key length: ${key.length} bytes"))
    else
      try {
        Right(fromJava(new SecretKeySpec(key, "AES")))
      } catch {
        case e: IllegalArgumentException => Left(e)
      }
  }

  def fromJava[Alg](key: JSecretKey): SecretKey[Alg] = JavaSecretKey(
    delegate = key
  )
}
