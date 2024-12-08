package crypto4s

import crypto4s.algorithm.Argon2
import zio.Scope
import zio.test.*

object Argon2HashingSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Argon2Hashing") {
    test("Default hashing") {
      checkAll(Gen.string) { string =>
        val hash1 = string.hash[Argon2]
        val hash2 = (string + "a").hash[Argon2]
        val hash3 = string.hash[Argon2]

        assertTrue(
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a"),
          hash1.hash.length == 32,
          hash1.`type` == Argon2.Type.Argon2id,
          hash1.version == Argon2.Version.V13,
          hash1.salt == None,
          hash1.memory == MemorySize.mb(64),
          hash1.iterations == 2,
          hash1.length == 32,
          hash1.parallelism == 1
        )
      }
    }
    test("Custom hashing") {
      checkAll(Gen.string, Gen.listOf1(Gen.byte)) { case (string, salt) =>
        given Argon2Hashing[String] = Argon2Hashing[String]()
          .withVersion(Argon2.Version.V10)
          .withSalt(salt.toArray)
          .withIterations(3)
          .withLength(40)
          .withParallelism(2)

        val hash1 = string.hash[Argon2]
        val hash2 = (string + "a").hash[Argon2]
        val hash3 = string.hash[Argon2]

        assertTrue(
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a"),
          hash1.hash.length == 40,
          hash1.`type` == Argon2.Type.Argon2id,
          hash1.version == Argon2.Version.V10,
          hash1.salt.get == salt.toArray,
          hash1.memory == MemorySize.mb(64),
          hash1.iterations == 3,
          hash1.length == 40,
          hash1.parallelism == 2
        )
      }
    }
  }
}
