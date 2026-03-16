package crypto4s

import zio.Scope
import zio.ZIO
import zio.test.*

object KeyPairSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("KeyPairSpec") {
    suiteAll("encrypt and decrypt") {
      test("string: algorithm=RSA") {
        val keyPair = KeyPair.RSA()

        checkAll(Gen.string) { data =>
          val encrypted = keyPair.encrypt(data)
          val decrypted = keyPair.decrypt(encrypted)

          for {
            decrypted <- ZIO.fromEither(decrypted)
          } yield {
            assertTrue(
              data == decrypted
            )
          }
        }
      }
      test("secretKey: algorithm=RSA") {
        val dek     = SecretKey.AES()
        val keyPair = KeyPair.RSA()

        check(Gen.string) { data =>
          val encryptedData      = dek.encrypt(data)
          val encryptedSecretKey = keyPair.encrypt(dek)

          for {
            decryptedSecretKey <- keyPair.decrypt(encryptedSecretKey)
            decryptedData      <- decryptedSecretKey.decrypt(encryptedData)
          } yield {
            assertTrue(data == decryptedData)
          }
        }
      }
    }

    test("decrypting with wrong key returns IntegrityCheckFailed") {
      val keyPair1 = KeyPair.RSA()
      val keyPair2 = KeyPair.RSA()

      val encrypted = keyPair1.encrypt("secret")
      val wrongKeyDecrypted = Encrypted[algorithm.RSA, String](encrypted.blob)
      val result = keyPair2.privateKey.decrypt(wrongKeyDecrypted)

      assertTrue(result.left.exists(_.isInstanceOf[DecryptionException.IntegrityCheckFailed]))
    }

    test("RSA.transformation is compatible with bare RSA algorithm") {
      import javax.crypto.Cipher
      val keyPair = KeyPair.RSA()

      val plaintext = "cross-cipher compatibility".getBytes("UTF-8")

      val encryptCipher = Cipher.getInstance("RSA")
      encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.publicKey.asJava)
      val encrypted = encryptCipher.doFinal(plaintext)

      val decryptCipher = Cipher.getInstance(algorithm.RSA.transformation)
      decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.privateKey.asJava)
      val decrypted = decryptCipher.doFinal(encrypted)

      assertTrue(plaintext.sameElements(decrypted))
    }

    suiteAll("sign and verify") {
      test("string: algorithm=RSA") {
        val keyPair = KeyPair.RSA()

        checkAll(Gen.const("test")) { data =>
          val signature = keyPair.sign(data)
          val verified  = keyPair.verify(data, signature)

          assertTrue(verified)
        }
      }
      test("secretKey: algorithm=RSA") {
        val dek     = SecretKey.AES()
        val keyPair = KeyPair.RSA()

        check(Gen.string) { data =>
          val encryptedData      = dek.encrypt(data)
          val encryptedSecretKey = keyPair.encrypt(dek)

          for {
            decryptedSecretKey <- keyPair.decrypt(encryptedSecretKey)
            decryptedData      <- decryptedSecretKey.decrypt(encryptedData)
            signature = keyPair.sign(decryptedData)
          } yield {
            assertTrue(keyPair.verify(decryptedData, signature))
          }
        }
      }
    }
  }
}
