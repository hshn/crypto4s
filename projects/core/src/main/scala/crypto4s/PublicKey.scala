package crypto4s

import java.security.KeyFactory
import java.security.PublicKey as JPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec

trait PublicKey[Alg] { self =>
  def encrypt[A: BlobEncoder](a: A)(using encrypting: Encrypting[Alg, PublicKey[Alg]]): Encrypted[Alg, A] =
    encrypting.encrypt(self, a)
  def verify[A: BlobEncoder, SignAlg](a: A, signature: Signed[SignAlg, A])(using verification: Verification[SignAlg, Alg]): Boolean =
    verification.verify(key = self, a = a, signature = signature)

  def asJava: JPublicKey
}

object PublicKey {
  def RSA(key: Array[Byte]): Either[InvalidKeySpecException, PublicKey[algorithm.RSA]] = try {
    val keySpec    = new X509EncodedKeySpec(key)
    val keyFactory = KeyFactory.getInstance("RSA")
    val publicKey  = keyFactory.generatePublic(keySpec)

    Right(fromJava(publicKey))
  } catch {
    case e: InvalidKeySpecException => Left(e)
  }

  def fromJava[Alg](key: JPublicKey): PublicKey[Alg] = JavaPublicKey(
    delegate = key
  )
}
