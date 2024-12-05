package cipher4s

import zio.Scope
import zio.ZIO
import zio.test.*

object KeyPairSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("KeyPairSpec") {
    suiteAll("encrypt and decrypt") {
      test("string: algorithm=RSA") {
        val keyPair = KeyPair.genRSA()

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
        val keyPair = KeyPair.genRSA()

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

    suiteAll("sign and verify") {
      test("string: algorithm=RSA") {
        val keyPair = KeyPair.genRSA()

        checkAll(Gen.const("test")) { data =>
          val signature = keyPair.sign(data)
          val verified  = keyPair.verify(data, signature)

          assertTrue(verified)
        }
      }
      test("secretKey: algorithm=RSA") {
        val dek     = SecretKey.AES()
        val keyPair = KeyPair.genRSA()

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
