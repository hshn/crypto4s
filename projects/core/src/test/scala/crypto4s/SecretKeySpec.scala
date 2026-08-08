package crypto4s

import zio.Scope
import zio.ZIO
import zio.test.Gen
import zio.test.Spec
import zio.test.TestEnvironment
import zio.test.ZIOSpecDefault
import zio.test.assertTrue
import zio.test.check

object SecretKeySpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("SecretKey") {
    suiteAll("encrypt and decrypt") {
      test("string(algorithm=aes256)") {
        val secretKey = SecretKey.AES()

        check(Gen.alphaNumericStringBounded(0, 256)) { data =>
          val encrypted = secretKey.encrypt(data)

          for {
            decrypted <- ZIO.fromEither(secretKey.decrypt(encrypted))
          } yield {
            assertTrue(decrypted == data)
          }
        }
      }

      test("secretKey(algorithm=aes256)") {
        val dek       = SecretKey.AES()
        val secretKey = SecretKey.AES()

        check(
          Gen.alphaNumericStringBounded(0, 256)
        ) { data =>
          val encryptedData = secretKey.encrypt(data)
          val encryptedKey  = dek.encrypt(secretKey)

          for {
            decryptedKey  <- ZIO.fromEither(dek.decrypt(encryptedKey))
            decryptedData <- ZIO.fromEither(decryptedKey.decrypt(encryptedData))
          } yield {
            assertTrue(data == decryptedData)
          }
        }
      }

      test("ciphertext too short returns InvalidCiphertext") {
        val secretKey = SecretKey.AES()
        val tooShort  = Encrypted[algorithm.AES, String](Blob.wrap(Array[Byte](1, 2, 3)))
        val result    = secretKey.decrypt(tooShort)

        assertTrue(result.left.exists(_.isInstanceOf[DecryptionException.InvalidCiphertext]))
      }

      test("tampered ciphertext returns IntegrityCheckFailed") {
        val secretKey = SecretKey.AES()

        check(Gen.alphaNumericStringBounded(1, 256)) { data =>
          val encrypted = secretKey.encrypt(data)
          val bytes     = encrypted.blob.toByteArray
          bytes(bytes.length - 1) = (bytes(bytes.length - 1) ^ 0xff).toByte
          val tampered = Encrypted[algorithm.AES, String](Blob.wrap(bytes))

          val result = secretKey.decrypt(tampered)
          assertTrue(result.left.exists(_.isInstanceOf[DecryptionException.IntegrityCheckFailed]))
        }
      }
    }
  }
}
