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

object BlobEncoderSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("BlobEncoder") {
    test("contraMap") {
      given BlobEncoder[Instant] = BlobEncoder[String].contraMap(_.toString)

      checkAll(Gen.instant) { instant =>
        assertTrue(
          instant.blob == Blob(instant.toString.getBytes)
        )
      }
    }
    test("toHexString") {
      checkAll(Gen.string) { string =>
        val hash = string.hashed[SHA256]
        val hex  = hash.blob.toHexString

        assertTrue(
          hex.length == 64,
          hex.matches("[0-9a-f]+")
        )
      }
    }
    test("toBase64String") {
      checkAll(Gen.string) { string =>
        val hash    = string.hashed[SHA256]
        val base64  = hash.blob.toBase64.toUtf8String
        val decoded = Base64.getDecoder.decode(base64)

        assertTrue(
          base64.matches("[A-Za-z0-9+/]+=*"),
          hash.hash == Blob(decoded)
        )
      }
    }
    test("toUrlBase64String") {
      checkAll(Gen.string) { string =>
        val hash    = string.hashed[SHA256]
        val base64  = hash.blob.toUrlBase64.toUtf8String
        val decoded = Base64.getUrlDecoder.decode(base64)

        assertTrue(
          base64.matches("[A-Za-z0-9_-]+"),
          hash.hash == Blob(decoded)
        )
      }
    }
  }
}
