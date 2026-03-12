package crypto4s

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey as JSecretKey
import javax.crypto.spec.SecretKeySpec

trait SecretKey[Alg] { self =>
  def encrypt[A: BlobEncoder](a: A)(using encrypting: Encrypting[Alg, SecretKey[Alg]]): Encrypted[Alg, A] =
    encrypting.encrypt(self, a)
  def decrypt[A: Deserializable](encrypted: Encrypted[Alg, A])(using decrypting: Decrypting[Alg, SecretKey[Alg]]): Either[RuntimeException, A] =
    decrypting.decrypt(self, encrypted)

  def asJava: JSecretKey
}

object SecretKey {
  def AES(size: Int = 256): SecretKey[algorithm.AES] = {
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(size)
    val key = keyGen.generateKey()

    fromJava(key)
  }

  def AES(key: Array[Byte]): Either[IllegalArgumentException, SecretKey[algorithm.AES]] = {
    for {
      keySpec <-
        try {
          Right(new SecretKeySpec(key, "AES"))
        } catch {
          case e: IllegalArgumentException => Left(e)
        }
    } yield {
      fromJava(keySpec)
    }
  }

  def fromJava(key: JSecretKey): SecretKey[algorithm.AES] = JavaSecretKey(
    delegate = key
  )
}

private[crypto4s] case class JavaSecretKey[Alg](
  delegate: JSecretKey
) extends SecretKey[Alg] {

  override def asJava: JSecretKey = delegate
}
