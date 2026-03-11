package crypto4s

import crypto4s.algorithm.HmacSHA1
import crypto4s.algorithm.HmacSHA256
import zio.Scope
import zio.ZIO
import zio.test.Gen
import zio.test.Spec
import zio.test.TestEnvironment
import zio.test.ZIOSpecDefault
import zio.test.assertTrue
import zio.test.checkAll

object MacingSpec extends ZIOSpecDefault {
  private val genKey = Gen.vectorOfBounded(16, 64)(Gen.byte).map(_.toArray)

  private val genHmacSHA1Key   = genKey.mapZIO(key => ZIO.fromEither(MacKey.hmacSHA1(key)).orDie)
  private val genHmacSHA256Key = genKey.mapZIO(key => ZIO.fromEither(MacKey.hmacSHA256(key)).orDie)

  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Macing") {
    test("HmacSHA1: same key and data produce verifiable MAC") {
      checkAll(Gen.string, genHmacSHA1Key) { (string, key) =>
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
      checkAll(Gen.string, genHmacSHA1Key) { (string, key) =>
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
        key1 <- genHmacSHA1Key
        key2 <- genHmacSHA1Key if !java.util.Arrays.equals(key1.asJava.getEncoded, key2.asJava.getEncoded)
      } yield (key1, key2)

      checkAll(Gen.string, genTwoKeys) { case (string, (key1, key2)) =>
        val mac1 = string.maced[HmacSHA1](key1)
        val mac2 = string.maced[HmacSHA1](key2)

        assertTrue(!mac1.verify(mac2))
      }
    }
    test("HmacSHA256: same key and data produce verifiable MAC") {
      checkAll(Gen.string, genHmacSHA256Key) { (string, key) =>
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
      checkAll(Gen.string, genHmacSHA256Key) { (string, key) =>
        val mac1 = string.maced[HmacSHA256](key)
        val mac2 = (string + "a").maced[HmacSHA256](key)

        assertTrue(
          !mac1.verify(mac2),
          mac1 != mac2
        )
      }
    }
    test("HmacSHA256: Blob conversion") {
      checkAll(Gen.string, genHmacSHA256Key) { (string, key) =>
        val maced  = string.maced[HmacSHA256](key)
        val asBlob = maced.blob
        val asHex  = maced.asHexString

        assertTrue(
          asBlob.sameElements(maced.mac),
          asHex.length == 64
        )
      }
    }
    test("MacKey.hmacSHA1() generates a usable key") {
      val key   = MacKey.hmacSHA1()
      val maced = "hello".maced[HmacSHA1](key)

      assertTrue(
        maced.mac.length == 20,
        maced.verify("hello".maced[HmacSHA1](key))
      )
    }
    test("MacKey.hmacSHA256() generates a usable key") {
      val key   = MacKey.hmacSHA256()
      val maced = "hello".maced[HmacSHA256](key)

      assertTrue(
        maced.mac.length == 32,
        maced.verify("hello".maced[HmacSHA256](key))
      )
    }
    test("MacKey.hmacSHA256(size) generates a key with specified size") {
      val key   = MacKey.hmacSHA256(512)
      val maced = "hello".maced[HmacSHA256](key)

      assertTrue(
        key.asJava.getEncoded.length == 64,
        maced.mac.length == 32,
        maced.verify("hello".maced[HmacSHA256](key))
      )
    }
    test("MacKey.hmacSHA256() generates unique keys") {
      val key1 = MacKey.hmacSHA256()
      val key2 = MacKey.hmacSHA256()
      val mac1 = "hello".maced[HmacSHA256](key1)
      val mac2 = "hello".maced[HmacSHA256](key2)

      assertTrue(!mac1.verify(mac2))
    }
    test("MacKey.hmacSHA256(key) returns Left for empty key") {
      assertTrue(MacKey.hmacSHA256(Array.empty[Byte]).isLeft)
    }
    test("MacKey.hmacSHA1(key) returns Left for empty key") {
      assertTrue(MacKey.hmacSHA1(Array.empty[Byte]).isLeft)
    }
    test("equalities") {
      val strings = for {
        str1 <- Gen.string
        str2 <- Gen.string if str1 != str2
      } yield (str1, str2)

      checkAll(strings, genHmacSHA256Key) { case ((str1, str2), key) =>
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
