package crypto4s

import zio.Scope
import zio.test.*

object MemorySizeSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("MemorySize") {
    test("kb keeps the requested size for every Int") {
      check(Gen.int) { kb =>
        assertTrue(MemorySize.kb(kb).toKb == kb.toLong)
      }
    }
    test("mb keeps the requested size for every Int") {
      check(Gen.int) { mb =>
        assertTrue(MemorySize.mb(mb).toMb == mb.toLong)
      }
    }
    test("sizes beyond 2GiB do not wrap around") {
      assertTrue(
        MemorySize.mb(2048).bytes == 2147483648L,
        MemorySize.mb(4097).bytes == 4296015872L,
        MemorySize.kb(2097152).bytes == 2147483648L
      )
    }
  }
}
