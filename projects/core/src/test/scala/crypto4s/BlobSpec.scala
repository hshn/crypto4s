package crypto4s

import zio.Scope
import zio.test.Gen
import zio.test.Spec
import zio.test.TestEnvironment
import zio.test.ZIOSpecDefault
import zio.test.assertTrue
import zio.test.checkAll

object BlobSpec extends ZIOSpecDefault {
  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Blob") {
    test("equals: same content") {
      checkAll(Gen.listOf(Gen.byte)) { bytes =>
        val arr = bytes.toArray
        val a   = Blob(arr)
        val b   = Blob(arr)

        assertTrue(a == b)
      }
    }
    test("equals: different content") {
      val gen = for {
        b1 <- Gen.listOf1(Gen.byte).map(_.toArray)
        b2 <- Gen.listOf1(Gen.byte).map(_.toArray) if !java.util.Arrays.equals(b1, b2)
      } yield (b1, b2)

      checkAll(gen) { case (b1, b2) =>
        assertTrue(Blob(b1) != Blob(b2))
      }
    }
    test("hashCode: same content produces same hashCode") {
      checkAll(Gen.listOf(Gen.byte)) { bytes =>
        val arr = bytes.toArray
        assertTrue(Blob(arr).## == Blob(arr).##)
      }
    }
    test("toString: hex representation") {
      val blob = Blob(Array[Byte](0x0a, 0x1b, 0x2c))
      assertTrue(blob.toString == "0a1b2c")
    }
    test("toByteArray: defensive copy") {
      val original = Array[Byte](1, 2, 3)
      val blob     = Blob(original)
      original(0) = 99.toByte

      assertTrue(blob.toByteArray(0) == 1.toByte)
    }
    test("toUtf8String") {
      val blob = Blob("hello".getBytes(java.nio.charset.StandardCharsets.UTF_8))
      assertTrue(blob.toUtf8String == "hello")
    }
  }
}
