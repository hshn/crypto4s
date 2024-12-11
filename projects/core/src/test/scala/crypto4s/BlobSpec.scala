package crypto4s

import crypto4s.algorithm.SHA256
import java.time.Instant
import java.util.Base64
import zio.Scope
import zio.test.Gen
import zio.test.Spec
import zio.test.TestEnvironment
import zio.test.ZIOSpecDefault
import zio.test.assertTrue
import zio.test.checkAll

object BlobSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Blob") {
    test("contraMap") {
      given Blob[Instant] = Blob[String].contraMap(_.toString)

      checkAll(Gen.instant) { instant =>
        assertTrue(
          instant.blob sameElements instant.toString.getBytes
        )
      }
    }
    test("toHexString") {
      checkAll(Gen.string) { string =>
        val hash = string.hashed[SHA256]
        val hex  = hash.asHexString

        assertTrue(
          hex.length == 64,
          hex.matches("[0-9a-f]+")
        )
      }
    }
    test("toBase64String") {
      checkAll(Gen.string) { string =>
        val hash    = string.hashed[SHA256]
        val base64  = hash.asBase64.asString
        val decoded = Base64.getDecoder.decode(base64)

        assertTrue(
          base64.matches("[A-Za-z0-9+/]+=*"),
          decoded == hash.hash
        )
      }
    }
    test("toUrlBase64String") {
      checkAll(Gen.string) { string =>
        val hash    = string.hashed[SHA256]
        val base64  = hash.asUrlBase64.asString
        val decoded = Base64.getUrlDecoder.decode(base64)

        assertTrue(
          base64.matches("[A-Za-z0-9_-]+"),
          decoded == hash.hash
        )
      }
    }
  }
}
