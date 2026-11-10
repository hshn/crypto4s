package crypto4s

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
          val encrypted: Encrypted[algorithm.AESGCM, String] = secretKey.encrypt(data)

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
          val tampered = Encrypted[algorithm.AESGCM, String](Blob.wrap(bytes))

          val result = secretKey.decrypt(tampered)
          assertTrue(result.isLeft)
        }
      }

      test("ciphertext too short to hold an IV and a tag is reported as a decryption failure") {
        val secretKey = SecretKey.AES()

        checkAll(Gen.fromIterable(Seq(0, 11, 27, 28))) { length =>
          val short = Encrypted[algorithm.AESGCM, String](Blob.wrap(Array.fill[Byte](length)(0)))

          assertTrue(secretKey.decrypt(short).is(_.left).getMessage == "Failed to decrypt")
        }
      }

      test("produces AES-GCM ciphertext a standard decryptor can read") {
        val secretKey = SecretKey.AES()
        val plaintext = "interoperable"

        val ciphertext = secretKey.encrypt(plaintext).blob.toByteArray

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey.asJava, new GCMParameterSpec(128, ciphertext.take(12)))
        val decrypted = cipher.doFinal(ciphertext.drop(12))

        assertTrue(new String(decrypted, "UTF-8") == plaintext)
      }

      test("decrypts AES-GCM ciphertext from a standard encryptor") {
        val secretKey = SecretKey.AES()
        val plaintext = "interoperable"

        val iv     = Array.fill[Byte](12)(0x07)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey.asJava, new GCMParameterSpec(128, iv))
        val ciphertext = iv ++ cipher.doFinal(plaintext.getBytes("UTF-8"))

        val decrypted = secretKey.decrypt(Encrypted[algorithm.AESGCM, String](Blob.wrap(ciphertext)))

        assertTrue(decrypted == Right(plaintext))
      }

      test("a ciphertext that names only the key algorithm does not compile as decryptable") {
        for {
          namingScheme  <- typeCheck("""SecretKey.AES().decrypt(Encrypted[algorithm.AESGCM, String](Blob.wrap(Array.emptyByteArray)))""")
          namingKeyOnly <- typeCheck("""SecretKey.AES().decrypt(Encrypted[algorithm.AES, String](Blob.wrap(Array.emptyByteArray)))""")
        } yield assertTrue(namingScheme.isRight, namingKeyOnly.isLeft)
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

      test("treats an empty context as no context") {
        val secretKey = SecretKey.AES()

        check(Gen.string) { data =>
          val boundToEmpty: Encrypted[algorithm.AESGCM, String] = secretKey.encrypt(data, context = "")
          val unbound: Encrypted[algorithm.AESGCM, String]      = secretKey.encrypt(data)

          assertTrue(
            secretKey.decrypt(boundToEmpty) == Right(data),
            secretKey.decrypt(unbound, context = "") == Right(data)
          )
        }
      }

      test("binds the context as GCM additional authenticated data a standard decryptor can verify") {
        val secretKey = SecretKey.AES()
        val plaintext = "interoperable"

        val ciphertext = secretKey.encrypt(plaintext, context = "users/42").blob.toByteArray

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey.asJava, new GCMParameterSpec(128, ciphertext.take(12)))
        cipher.updateAAD("users/42".getBytes("UTF-8"))
        val decrypted = cipher.doFinal(ciphertext.drop(12))

        assertTrue(new String(decrypted, "UTF-8") == plaintext)
      }

      test("decrypts GCM ciphertext a standard encryptor bound to the context") {
        val secretKey = SecretKey.AES()
        val plaintext = "interoperable"

        val iv     = Array.fill[Byte](12)(0x07)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey.asJava, new GCMParameterSpec(128, iv))
        cipher.updateAAD("users/42".getBytes("UTF-8"))
        val ciphertext = iv ++ cipher.doFinal(plaintext.getBytes("UTF-8"))

        val decrypted = secretKey.decrypt(Encrypted[algorithm.AESGCM, String](Blob.wrap(ciphertext)), context = "users/42")

        assertTrue(decrypted == Right(plaintext))
      }
    }
  }

  private val distinctContexts = (Gen.string <*> Gen.string).filter((bound, other) => bound != other)
}
