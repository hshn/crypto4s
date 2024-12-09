package crypto4s

import zio.Scope
import zio.test.Spec
import zio.test.TestEnvironment
import zio.test.ZIOSpecDefault
import zio.test.assertTrue

object EncryptedSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Encrypted") {
    test("equals") {
      val a = Encrypted[Any, String](Array(1, 2, 3))
      val b = Encrypted[Any, String](Array(2, 3, 4))
      val c = Encrypted[Any, String](Array(1, 2, 3))

      assertTrue(
        a != b,
        a == c,
        b != c
      )
    }
    test("hashCode()") {
      val a = Encrypted[Any, String](Array(1, 2, 3))
      val b = Encrypted[Any, String](Array(2, 3, 4))
      val c = Encrypted[Any, String](Array(1, 2, 3))

      assertTrue(
        a.## != b.##,
        a.## == c.##,
        b.## != c.##
      )
    }
  }
}
