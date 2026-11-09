package crypto4s

import java.math.BigInteger
import java.security.interfaces.RSAPublicKey
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.encodings.OAEPEncoding
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.util.BigIntegers
import zio.Scope
import zio.ZIO
import zio.test.*

object KeyPairSpec extends ZIOSpecDefault {
  private def oaepWithSha256(label: Array[Byte] = Array.emptyByteArray) =
    new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA256Digest(), label)

  // RSA-2048 with OAEP SHA-256 fits 190 bytes; 63 chars stay within it even at 3 UTF-8 bytes each
  private val rsaPlaintext = Gen.stringBounded(0, 63)(Gen.unicodeChar)

  private val distinctContexts = (Gen.string <*> Gen.string).filter((bound, other) => bound != other)

  private def rsaCiphertext(bytes: Array[Byte]) = Encrypted[algorithm.RSA, Array[Byte]](Blob.wrap(bytes))

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

    suiteAll("context") {
      test("decrypts with the same context") {
        val keyPair = KeyPair.RSA()

        check(rsaPlaintext, Gen.string) { (data, context) =>
          val encrypted = keyPair.encrypt(data, context = context)

          assertTrue(keyPair.decrypt(encrypted, context = context) == Right(data))
        }
      }
      test("rejects a different context") {
        val keyPair = KeyPair.RSA()

        check(rsaPlaintext, distinctContexts) { case (data, (bound, other)) =>
          val encrypted = keyPair.encrypt(data, context = bound)

          assertTrue(keyPair.decrypt(encrypted, context = other).is(_.left).getMessage == "Failed to decrypt")
        }
      }
      test("rejects a missing context") {
        val keyPair = KeyPair.RSA()

        check(rsaPlaintext, Gen.string1(Gen.unicodeChar)) { (data, context) =>
          val encrypted = keyPair.encrypt(data, context = context)

          assertTrue(keyPair.decrypt(encrypted).is(_.left).getMessage == "Failed to decrypt")
        }
      }
      test("rejects a context the ciphertext was not bound to") {
        val keyPair = KeyPair.RSA()

        check(rsaPlaintext, Gen.string1(Gen.unicodeChar)) { (data, context) =>
          val encrypted = keyPair.encrypt(data)

          assertTrue(keyPair.decrypt(encrypted, context = context).is(_.left).getMessage == "Failed to decrypt")
        }
      }
    }

    suiteAll("RSA ciphertext format") {
      test("a PKCS#1 v1.5 block forged from the public key is not accepted") {
        val keyPair   = KeyPair.RSA()
        val publicKey = keyPair.publicKey.asJava.asInstanceOf[RSAPublicKey]
        val keyLength = (publicKey.getModulus.bitLength + 7) / 8

        val message = "forged".getBytes("UTF-8")
        val filler  = Array.fill[Byte](keyLength - message.length - 3)(0x42)
        val block   = Array[Byte](0x00, 0x02) ++ filler ++ Array[Byte](0x00) ++ message

        val forged = new BigInteger(1, block).modPow(publicKey.getPublicExponent, publicKey.getModulus)

        val decrypted = keyPair.decrypt(rsaCiphertext(BigIntegers.asUnsignedByteArray(keyLength, forged)))

        assertTrue(decrypted.is(_.left).getMessage == "Failed to decrypt")
      }
      test("decrypts OAEP SHA-256 ciphertext from another implementation") {
        val keyPair   = KeyPair.RSA()
        val plaintext = "interoperable".getBytes("UTF-8")

        val encoding = oaepWithSha256()
        encoding.init(true, PublicKeyFactory.createKey(keyPair.publicKey.asJava.getEncoded))
        val ciphertext = encoding.processBlock(plaintext, 0, plaintext.length)

        val decrypted = keyPair.decrypt(rsaCiphertext(ciphertext))

        assertTrue(decrypted.map(_.toSeq) == Right(plaintext.toSeq))
      }
      test("produces OAEP SHA-256 ciphertext another implementation can decrypt") {
        val keyPair   = KeyPair.RSA()
        val plaintext = "interoperable"

        val ciphertext = keyPair.encrypt(plaintext).blob.toByteArray

        val encoding = oaepWithSha256()
        encoding.init(false, PrivateKeyFactory.createKey(keyPair.privateKey.asJava.getEncoded))
        val decrypted = encoding.processBlock(ciphertext, 0, ciphertext.length)

        assertTrue(new String(decrypted, "UTF-8") == plaintext)
      }
      test("binds the context as the OAEP label for another implementation") {
        val keyPair   = KeyPair.RSA()
        val plaintext = "interoperable"

        val ciphertext = keyPair.encrypt(plaintext, context = "users/42").blob.toByteArray

        val encoding = oaepWithSha256(label = "users/42".getBytes("UTF-8"))
        encoding.init(false, PrivateKeyFactory.createKey(keyPair.privateKey.asJava.getEncoded))
        val decrypted = encoding.processBlock(ciphertext, 0, ciphertext.length)

        assertTrue(new String(decrypted, "UTF-8") == plaintext)
      }
      test("decrypts OAEP ciphertext labelled by another implementation") {
        val keyPair   = KeyPair.RSA()
        val plaintext = "interoperable".getBytes("UTF-8")

        val encoding = oaepWithSha256(label = "users/42".getBytes("UTF-8"))
        encoding.init(true, PublicKeyFactory.createKey(keyPair.publicKey.asJava.getEncoded))
        val ciphertext = encoding.processBlock(plaintext, 0, plaintext.length)

        val decrypted = keyPair.decrypt(rsaCiphertext(ciphertext), context = "users/42")

        assertTrue(decrypted.map(_.toSeq) == Right(plaintext.toSeq))
      }
      test("malformed ciphertext is reported as a decryption failure") {
        val keyPair    = KeyPair.RSA()
        val ciphertext = keyPair.encrypt("secret").blob.toByteArray

        val tampered  = ciphertext.updated(ciphertext.length - 1, (ciphertext.last ^ 0x01).toByte)
        val truncated = ciphertext.dropRight(1)
        val extended  = ciphertext :+ 0x00.toByte

        checkAll(Gen.fromIterable(Seq(tampered, truncated, extended, Array.emptyByteArray))) { malformed =>
          assertTrue(keyPair.decrypt(rsaCiphertext(malformed)).is(_.left).getMessage == "Failed to decrypt")
        }
      }
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
