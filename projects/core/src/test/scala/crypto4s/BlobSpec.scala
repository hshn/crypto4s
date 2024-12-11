package crypto4s

import java.time.Instant
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
  }
}
