package crypto4s

import crypto4s.algorithm.RSA
import java.security.KeyPairGenerator

case class KeyPair[Alg](
  privateKey: PrivateKey[Alg],
  publicKey: PublicKey[Alg]
) {
  val algorithm: Alg = privateKey.algorithm

  def encrypt[A: Blob](a: A): Encrypted[A]                                             = publicKey.encrypt(a)
  def decrypt[A: Deserializable](encrypted: Encrypted[A]): Either[RuntimeException, A] = privateKey.decrypt(encrypted)

  def sign[A: Blob, SignAlg](a: A)(using Signing[SignAlg, Alg]): Signed[SignAlg, A] = privateKey.sign(a)
  def verify[A: Blob, SignAlg](a: A, signature: Signed[SignAlg, A])(using Verification[SignAlg, Alg]): Boolean =
    publicKey.verify(a, signature)
}

object KeyPair {
  def RSA(
    keySize: Int = 2048
  ): KeyPair[algorithm.RSA] = {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(keySize)

    val keyPair = keyGen.generateKeyPair()

    KeyPair(
      privateKey = JavaPrivateKey(
        algorithm = algorithm.RSA,
        delegate = keyPair.getPrivate
      ),
      publicKey = JavaPublicKey(
        algorithm = algorithm.RSA,
        delegate = keyPair.getPublic
      )
    )
  }
}
