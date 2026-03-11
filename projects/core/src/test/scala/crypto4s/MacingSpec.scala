package crypto4s

import crypto4s.algorithm.HmacSHA1
import crypto4s.algorithm.HmacSHA256
import zio.Scope
import zio.test.Gen
import zio.test.Spec
import zio.test.TestEnvironment
import zio.test.ZIOSpecDefault
import zio.test.assertTrue
import zio.test.checkAll

object MacingSpec extends ZIOSpecDefault {
  private val genKey = Gen.vectorOfBounded(16, 64)(Gen.byte).map(_.toArray)

  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Macing") {
    test("HmacSHA1: same key and data produce verifiable MAC") {
      checkAll(Gen.string, genKey) { (string, keyBytes) =>
        val key  = MacSecretKey.hmacSHA1(keyBytes)
        val mac1 = string.maced[HmacSHA1](key)
        val mac2 = string.maced[HmacSHA1](key)

        assertTrue(
          mac1.mac.length == 20,
          mac1.verify(mac2),
          mac1 == mac2
        )
      }
    }
    test("HmacSHA1: different data produce different MACs") {
      checkAll(Gen.string, genKey) { (string, keyBytes) =>
        val key  = MacSecretKey.hmacSHA1(keyBytes)
        val mac1 = string.maced[HmacSHA1](key)
        val mac2 = (string + "a").maced[HmacSHA1](key)

        assertTrue(
          !mac1.verify(mac2),
          mac1 != mac2
        )
      }
    }
    test("HmacSHA1: different keys produce different MACs") {
      val genTwoKeys = for {
        key1 <- genKey
        key2 <- genKey if !java.util.Arrays.equals(key1, key2)
      } yield (key1, key2)

      checkAll(Gen.string, genTwoKeys) { case (string, (keyBytes1, keyBytes2)) =>
        val mac1 = string.maced[HmacSHA1](MacSecretKey.hmacSHA1(keyBytes1))
        val mac2 = string.maced[HmacSHA1](MacSecretKey.hmacSHA1(keyBytes2))

        assertTrue(!mac1.verify(mac2))
      }
    }
    test("HmacSHA256: same key and data produce verifiable MAC") {
      checkAll(Gen.string, genKey) { (string, keyBytes) =>
        val key  = MacSecretKey.hmacSHA256(keyBytes)
        val mac1 = string.maced[HmacSHA256](key)
        val mac2 = string.maced[HmacSHA256](key)

        assertTrue(
          mac1.mac.length == 32,
          mac1.verify(mac2),
          mac1 == mac2
        )
      }
    }
    test("HmacSHA256: different data produce different MACs") {
      checkAll(Gen.string, genKey) { (string, keyBytes) =>
        val key  = MacSecretKey.hmacSHA256(keyBytes)
        val mac1 = string.maced[HmacSHA256](key)
        val mac2 = (string + "a").maced[HmacSHA256](key)

        assertTrue(
          !mac1.verify(mac2),
          mac1 != mac2
        )
      }
    }
    test("HmacSHA256: Blob conversion") {
      checkAll(Gen.string, genKey) { (string, keyBytes) =>
        val key    = MacSecretKey.hmacSHA256(keyBytes)
        val maced  = string.maced[HmacSHA256](key)
        val asBlob = maced.blob
        val asHex  = maced.asHexString

        assertTrue(
          asBlob.sameElements(maced.mac),
          asHex.length == 64
        )
      }
    }
    test("equalities") {
      val strings = for {
        str1 <- Gen.string
        str2 <- Gen.string if str1 != str2
      } yield (str1, str2)

      checkAll(strings, genKey) { case ((str1, str2), keyBytes) =>
        val key  = MacSecretKey.hmacSHA256(keyBytes)
        val mac1 = str1.maced[HmacSHA256](key)
        val mac2 = str1.maced[HmacSHA256](key)
        val mac3 = str2.maced[HmacSHA256](key)

        assertTrue(
          mac1 == mac2,
          mac1 != mac3,
          mac1.## == mac2.##,
          mac1.## != mac3.##
        )
      }
    }
  }
}
