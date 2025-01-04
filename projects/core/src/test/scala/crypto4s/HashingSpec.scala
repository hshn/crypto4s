package crypto4s

import crypto4s.algorithm.SHA1
import crypto4s.algorithm.SHA256
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
        val hash1: Hashed[SHA1, String] = string.hashed[SHA1]
        val hash2                       = (string + "a").hashed[SHA1]
        val hash3                       = string.hashed[SHA1]

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
        val hash1 = string.hashed[SHA256]
        val hash2 = (string + "a").hashed[SHA256]
        val hash3 = string.hashed[SHA256]

        assertTrue(
          hash1.hash.length == 32,
          !hash1.verify(hash2),
          hash1.verify(hash3),
          hash1.verify(of = string),
          !hash1.verify(of = string + "a")
        )
      }
    }
    test("equalities") {
      val strings = for {
        str1 <- Gen.string
        str2 <- Gen.string if str1 != str2
      } yield {
        (str1, str2)
      }

      checkAll(strings) { case (str1, str2) =>
        val hash1 = str1.hashed[SHA1]
        val hash2 = str1.hashed[SHA1]
        val hash3 = str2.hashed[SHA1]

        assertTrue(
          hash1 == hash2,
          hash1 != hash3,
          hash1.## == hash2.##,
          hash1.## != hash3.##
        )
      }
    }
  }
}
