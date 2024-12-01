package cipher4s

import zio.Scope
import zio.ZIO
import zio.test.*

object KeyPairSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("KeyPairSpec") {
    suiteAll("encrypt and decrypt") {
      test("string: algorithm=rs256") {
        val keyPair = KeyPair.genRS256()

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
      test("secretKey: algorithm=rs256") {
        val dek     = SecretKey.genAES256()
        val keyPair = KeyPair.genRS256()

        check(Gen.string) { data =>
          val encryptedData      = dek.encrypt(data)
          val encryptedSecretKey = keyPair.encrypt(dek)

          for {
            decryptedSecretKey <- (keyPair.decrypt(encryptedSecretKey))
            decryptedData      <- (decryptedSecretKey.decrypt(encryptedData))
          } yield {
            assertTrue(data == decryptedData)
          }
        }
      }
    }
  }
}
