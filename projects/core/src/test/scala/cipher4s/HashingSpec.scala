package cipher4s

import cipher4s.implicits.*
import java.security.MessageDigest
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
        val hash1 = string.toHashed[Algorithm.SHA1]
        val hash2 = (string + "a").toHashed[Algorithm.SHA1]
        val hash3 = string.toHashed[Algorithm.SHA1]

        assertTrue(
          hash1 != hash2,
          hash1 == hash3,
          hash1.hasSameHash(of = string),
          !hash1.hasSameHash(of = string + "a")
        )
      }
    }
    test("SHA256: String") {
      checkAll(Gen.string) { string =>
        val hash1 = string.toHashed[Algorithm.SHA256]
        val hash2 = (string + "a").toHashed[Algorithm.SHA256]
        val hash3 = string.toHashed[Algorithm.SHA256]

        assertTrue(
          hash1 != hash2,
          hash1 == hash3,
          hash1.hasSameHash(of = string),
          !hash1.hasSameHash(of = string + "a")
        )
      }
    }
    test("toHexString") {
      checkAll(Gen.string) { string =>
        val hash = string.toHashed[Algorithm.SHA256]
        val hex  = hash.toHexString

        assertTrue(
          hex.length == 64,
          hex.matches("[0-9a-f]+")
        )
      }
    }
    test("toBase64String") {
      checkAll(Gen.string) { string =>
        val hash    = string.toHashed[Algorithm.SHA256]
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
        val hash    = string.toHashed[Algorithm.SHA256]
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
