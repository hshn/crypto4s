package crypto4s

import crypto4s.algorithm.Argon2
import java.nio.charset.StandardCharsets.UTF_8
import java.util.HexFormat
import zio.Scope
import zio.test.*

object Argon2HashingSpec extends ZIOSpecDefault {
  private val lightHashing = Argon2Hashing().withMemory(MemorySize.kb(64)).withIterations(1)

  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Argon2Hashing") {
    test("Default hashing") {
      checkAll(Gen.string) { string =>
        val hash1 = string.hashed[Argon2]
        val hash2 = (string + "a").hashed[Argon2]
        val hash3 = string.hashed[Argon2]

        assertTrue(
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a"),
          hash1.hash.length == 32,
          hash1.parameters == Argon2.Parameters(
            `type` = Argon2.Type.Argon2id,
            version = Argon2.Version.V13,
            salt = None,
            memory = MemorySize.mb(64),
            iterations = 2,
            length = 32,
            parallelism = 1
          )
        )
      }
    }
    test("Custom hashing") {
      checkAll(Gen.string, Gen.listOf1(Gen.byte)) { case (string, salt) =>
        given Argon2Hashing = Argon2Hashing()
          .withVersion(Argon2.Version.V10)
          .withSalt(salt.toArray)
          .withIterations(3)
          .withLength(40)
          .withParallelism(2)

        val hashing2 = Argon2Hashing()
          .withVersion(Argon2.Version.V10)
          .withSalt(salt.toArray)
          .withIterations(3)
          .withLength(45)
          .withParallelism(2)

        val hash1 = string.hashed[Argon2]
        val hash2 = (string + "a").hashed[Argon2]
        val hash3 = string.hashed[Argon2]
        val hash4 = string.hashed(using hashing = hashing2)

        assertTrue(
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a"),
          hash1.hash.length == 40,
          hash1.parameters.`type` == Argon2.Type.Argon2id,
          hash1.parameters.version == Argon2.Version.V10,
          hash1.parameters.salt == Some(Blob(salt.toArray)),
          hash1.parameters.memory == MemorySize.mb(64),
          hash1.parameters.iterations == 3,
          hash1.parameters.length == 40,
          hash1.parameters.parallelism == 2,
          hash4.verify(of = string),
          !hash4.verify(of = string + "a")
        )
      }
    }
    test("Every type and version matches the Argon2 reference implementation") {
      val referenceHashes = List(
        (Argon2.Type.Argon2i, Argon2.Version.V10, "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694"),
        (Argon2.Type.Argon2i, Argon2.Version.V13, "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0"),
        (Argon2.Type.Argon2d, Argon2.Version.V10, "2ec0d925358f5830caf0c1cc8a3ee58b34505759428b859c79b72415f51f9221"),
        (Argon2.Type.Argon2d, Argon2.Version.V13, "955e5d5b163a1b60bba35fc36d0496474fba4f6b59ad53628666f07fb2f93eaf"),
        (Argon2.Type.Argon2id, Argon2.Version.V10, "980ebd24a4e667f16346f9d4a78b175728783613e0cc6fb17c2ec884b16435df"),
        (Argon2.Type.Argon2id, Argon2.Version.V13, "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
      )

      checkAll(Gen.fromIterable(referenceHashes)) { case (argon2Type, version, expected) =>
        val hash = Argon2Hashing(argon2Type).withVersion(version).withSalt("somesalt".getBytes(UTF_8)).hash("password")

        assertTrue(hash.hash.toHexString == expected)
      }
    }
    test("A hash does not verify under a different salt") {
      val salts = for {
        salt1 <- Gen.listOf1(Gen.byte)
        salt2 <- Gen.listOf1(Gen.byte) if salt1 != salt2
      } yield (salt1.toArray, salt2.toArray)

      check(Gen.string, salts) { case (string, (salt, otherSalt)) =>
        val hash           = lightHashing.withSalt(salt).hash(string)
        val underOtherSalt = Argon2Hash[String](hash.hash, hash.parameters.copy(salt = Some(Blob(otherSalt))))

        assertTrue(hash.verify(of = string), !underOtherSalt.verify(of = string))
      }
    }
    test("A hash keeps verifying after the caller overwrites its salt array") {
      val salt = Array.fill[Byte](16)(1)
      val hash = lightHashing.withSalt(salt).hash("password")

      salt(0) = 2

      assertTrue(hash.verify(of = "password"))
    }
    test("A random salt gives every hash its own 16-byte salt") {
      check(Gen.string) { string =>
        val hashing = lightHashing.withRandomSalt
        val hash1   = hashing.hash(string)
        val hash2   = hashing.hash(string)

        assertTrue(
          hash1.parameters.salt.map(_.length) == Some(16),
          hash1.parameters.salt != hash2.parameters.salt,
          hash1.verify(of = string),
          !hash1.verify(of = string + "a")
        )
      }
    }
    test("Hashes of the same input under different salts do not match each other") {
      check(Gen.string) { string =>
        val hashing = lightHashing.withRandomSalt

        assertTrue(!hashing.hash(string).verify(hashing.hash(string)))
      }
    }
    test("A hash stored without a salt stays verifiable") {
      val stored = Argon2Hash[String](
        hash = Blob(HexFormat.of.parseHex("b5bde7623f24af0a73f3a09947ec3ed2c77fc723755eab249ae7e81aaa2b7949")),
        parameters = Argon2.Parameters(
          `type` = Argon2.Type.Argon2id,
          version = Argon2.Version.V13,
          salt = None,
          memory = MemorySize.mb(64),
          iterations = 2,
          length = 32,
          parallelism = 1
        )
      )

      assertTrue(stored.verify(of = "password"), !stored.verify(of = "passwordz"))
    }
  }
}
