package crypto4s

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import zio.Scope
import zio.ZIO
import zio.test.*

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

      test("tampered ciphertext returns Left") {
        val secretKey = SecretKey.AES()

        check(Gen.alphaNumericStringBounded(1, 256)) { data =>
          val encrypted = secretKey.encrypt(data)
          val bytes     = encrypted.blob.toByteArray
          bytes(bytes.length - 1) = (bytes(bytes.length - 1) ^ 0xff).toByte
          val tampered = Encrypted[algorithm.AES, String](Blob.wrap(bytes))

          val result = secretKey.decrypt(tampered)
          assertTrue(result.isLeft)
        }
      }
    }

    suiteAll("context") {
      test("decrypts with the same context") {
        val secretKey = SecretKey.AES()

        check(Gen.string, Gen.string) { (data, context) =>
          val encrypted = secretKey.encrypt(data, context = context)

          assertTrue(secretKey.decrypt(encrypted, context = context) == Right(data))
        }
      }

      test("rejects a different context") {
        val secretKey = SecretKey.AES()

        check(Gen.string, distinctContexts) { case (data, (bound, other)) =>
          val encrypted = secretKey.encrypt(data, context = bound)

          assertTrue(secretKey.decrypt(encrypted, context = other).is(_.left).getMessage == "Failed to decrypt")
        }
      }

      test("rejects a missing context") {
        val secretKey = SecretKey.AES()

        check(Gen.string, Gen.string1(Gen.unicodeChar)) { (data, context) =>
          val encrypted = secretKey.encrypt(data, context = context)

          assertTrue(secretKey.decrypt(encrypted).is(_.left).getMessage == "Failed to decrypt")
        }
      }

      test("rejects a context the ciphertext was not bound to") {
        val secretKey = SecretKey.AES()

        check(Gen.string, Gen.string1(Gen.unicodeChar)) { (data, context) =>
          val encrypted = secretKey.encrypt(data)

          assertTrue(secretKey.decrypt(encrypted, context = context).is(_.left).getMessage == "Failed to decrypt")
        }
      }

      test("decrypts ciphertext produced without a context") {
        val secretKey = SecretKey.AES()

        check(Gen.string) { data =>
          val iv = new Array[Byte](12)
          new SecureRandom().nextBytes(iv)
          val cipher = Cipher.getInstance("AES/GCM/NoPadding")
          cipher.init(Cipher.ENCRYPT_MODE, secretKey.asJava, new GCMParameterSpec(128, iv))
          val stored = Encrypted[algorithm.AES, String](Blob.wrap(iv ++ cipher.doFinal(data.getBytes(StandardCharsets.UTF_8))))

          assertTrue(secretKey.decrypt(stored) == Right(data))
        }
      }
    }
  }

  private val distinctContexts = (Gen.string <*> Gen.string).filter((bound, other) => bound != other)
}
