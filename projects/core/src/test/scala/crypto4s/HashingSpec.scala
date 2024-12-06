package crypto4s

import crypto4s.Algorithm.SHA1
import crypto4s.implicits.*
import java.util.Base64
import zio.Scope
import zio.test.Gen
import zio.test.Spec
import zio.test.TestEnvironment
import zio.test.ZIOSpecDefault
import zio.test.assertTrue
import zio.test.checkAll

object HashingSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Hashing") {
    test("SHA1: String") {
      checkAll(Gen.string) { string =>
        val hash1: Hashed[SHA1, String] = string.hash[Algorithm.SHA1]
        val hash2                       = (string + "a").hash[Algorithm.SHA1]
        val hash3                       = string.hash[Algorithm.SHA1]

        assertTrue(
          hash1.hash.length == 20,
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a")
        )
      }
    }
    test("SHA256: String") {
      checkAll(Gen.string) { string =>
        val hash1 = string.hash[Algorithm.SHA256]
        val hash2 = (string + "a").hash[Algorithm.SHA256]
        val hash3 = string.hash[Algorithm.SHA256]

        assertTrue(
          hash1.hash.length == 32,
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a")
        )
      }
    }
    test("Argon2") {
      checkAll(Gen.string) { string =>
        val hash1 = string.hash[Algorithm.Argon2]
        val hash2 = (string + "a").hash[Algorithm.Argon2]
        val hash3 = string.hash[Algorithm.Argon2]

        assertTrue(
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a"),
          hash1.hash.length == 32,
          hash1.`type` == Algorithm.Argon2.Type.Argon2id,
          hash1.version == Algorithm.Argon2.Version.V13,
          hash1.salt == None,
          hash1.memory == MemorySize.mb(64),
          hash1.iterations == 2,
          hash1.length == 32,
          hash1.parallelism == 1
        )
      }
    }
    test("Argon2: custom") {
      checkAll(Gen.string, Gen.listOf1(Gen.byte)) { case (string, salt) =>
        given Argon2Hashing[String] = Hashing
          .Argon2id[String]
          .withVersion(Algorithm.Argon2.Version.V10)
          .withSalt(salt.toArray)
          .withIterations(3)
          .withLength(40)
          .withParallelism(2)

        val hash1 = string.hash[Algorithm.Argon2]
        val hash2 = (string + "a").hash[Algorithm.Argon2]
        val hash3 = string.hash[Algorithm.Argon2]

        assertTrue(
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a"),
          hash1.hash.length == 40,
          hash1.`type` == Algorithm.Argon2.Type.Argon2id,
          hash1.version == Algorithm.Argon2.Version.V10,
          hash1.salt.get == salt.toArray,
          hash1.memory == MemorySize.mb(64),
          hash1.iterations == 3,
          hash1.length == 40,
          hash1.parallelism == 2
        )
      }
    }
    test("toHexString") {
      checkAll(Gen.string) { string =>
        val hash = string.hash[Algorithm.SHA256]
        val hex  = hash.toHexString

        assertTrue(
          hex.length == 64,
          hex.matches("[0-9a-f]+")
        )
      }
    }
    test("toBase64String") {
      checkAll(Gen.string) { string =>
        val hash    = string.hash[Algorithm.SHA256]
        val base64  = hash.toBase64String
        val decoded = Base64.getDecoder.decode(base64)

        assertTrue(
          base64.matches("[A-Za-z0-9+/]+=*"),
          decoded == hash.hash
        )
      }
    }
    test("toUrlBase64String") {
      checkAll(Gen.string) { string =>
        val hash    = string.hash[Algorithm.SHA256]
        val base64  = hash.toUrlBase64String
        val decoded = Base64.getUrlDecoder.decode(base64)

        assertTrue(
          base64.matches("[A-Za-z0-9_-]+"),
          decoded == hash.hash
        )
      }
    }
  }
}
