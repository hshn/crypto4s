package crypto4s

import java.security.KeyPair as JKeyPair
import java.security.KeyPairGenerator

case class KeyPair[Alg](
  privateKey: PrivateKey[Alg],
  publicKey: PublicKey[Alg]
) {
  def encrypt[A: BlobEncoder](a: A)(using Encrypting[Alg, PublicKey[Alg]]): Encrypted[Alg, A] = publicKey.encrypt(a)
  def decrypt[A: Deserializable](encrypted: Encrypted[Alg, A])(using Decrypting[Alg, PrivateKey[Alg]]): Either[RuntimeException, A] =
    privateKey.decrypt(encrypted)

  def sign[A: BlobEncoder, SignAlg](a: A)(using Signing[SignAlg, Alg]): Signed[SignAlg, A]                            = privateKey.sign(a)
  def verify[A: BlobEncoder, SignAlg](a: A, signature: Signed[SignAlg, A])(using Verification[SignAlg, Alg]): Boolean =
    publicKey.verify(a, signature)
}

object KeyPair {
  def RSA(
    keySize: Int = 2048
  ): KeyPair[algorithm.RSA] = {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(keySize)

    val keyPair = keyGen.generateKeyPair()

    fromJava(keyPair)
  }

  def fromJava[Alg](
    keyPair: JKeyPair
  ): KeyPair[Alg] = KeyPair(
    privateKey = PrivateKey.fromJava(keyPair.getPrivate),
    publicKey = PublicKey.fromJava(keyPair.getPublic)
  )
}
