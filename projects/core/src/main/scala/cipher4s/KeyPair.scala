package cipher4s

import java.security.KeyPairGenerator

case class KeyPair[Alg](
  privateKey: PrivateKey[Alg],
  publicKey: PublicKey[Alg]
) {
  val algorithm: Alg = privateKey.algorithm

  def encrypt[A: Blob](a: A): Encrypted[A]                                             = publicKey.encrypt(a)
  def decrypt[A: Deserializable](encrypted: Encrypted[A]): Either[RuntimeException, A] = privateKey.decrypt(encrypted)
}

object KeyPair {
  def genRS256(
    keySize: Int = 2048
  ): KeyPair[Algorithm.RS256] = {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(keySize)

    val keyPair = keyGen.generateKeyPair()

    KeyPair(
      privateKey = JavaPrivateKey(
        algorithm = Algorithm.RS256,
        delegate = keyPair.getPrivate
      ),
      publicKey = JavaPublicKey(
        algorithm = Algorithm.RS256,
        delegate = keyPair.getPublic
      )
    )
  }
}
