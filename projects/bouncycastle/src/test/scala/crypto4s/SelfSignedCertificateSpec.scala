package crypto4s

import crypto4s.algorithm.AES
import crypto4s.algorithm.RS256
import crypto4s.algorithm.RSA
import java.security.Security
import java.time.Instant
import scala.compiletime.testing.typeChecks
import scala.concurrent.duration.*
import zio.Scope
import zio.test.*

object SelfSignedCertificateSpec extends ZIOSpecDefault {
  private val keyPair   = KeyPair.RSA()
  private val subject   = DistinguishedName.commonName("foo.example.com")
  private val notBefore = Instant.parse("2026-01-01T00:00:00Z")

  private def aesKeyPair: KeyPair[AES] = ???

  private def selfSigned: Certificate[RSA] = Certificate.selfSigned(
    keyPair = keyPair,
    algorithm = RS256,
    subject = subject,
    notBefore = notBefore,
    ttl = 3650.days
  )

  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Certificate.selfSigned") {
    test("certifies the key for the subject during the validity period") {
      val certificate = selfSigned

      assertTrue(
        certificate.publicKey == keyPair.publicKey,
        certificate.subject == subject,
        certificate.notBefore == notBefore,
        certificate.notAfter == Instant.parse("2035-12-30T00:00:00Z")
      )
    }
    test("rounds the validity period down to whole seconds") {
      val certificate = Certificate.selfSigned(
        keyPair = keyPair,
        algorithm = RS256,
        subject = subject,
        notBefore = Instant.parse("2026-01-01T00:00:00.999Z"),
        ttl = 1.day + 500.millis
      )

      assertTrue(
        certificate.notBefore == Instant.parse("2026-01-01T00:00:00Z"),
        certificate.notAfter == Instant.parse("2026-01-02T00:00:01Z")
      )
    }
    test("names the subject as its own issuer") {
      assertTrue(selfSigned.issuer == subject)
    }
    test("is signed by the certified key with the requested algorithm") {
      val certificate = selfSigned

      certificate.asJava.verify(keyPair.publicKey.asJava)

      assertTrue(certificate.asJava.getSigAlgName == "SHA256withRSA")
    }
    test("survives a DER round trip") {
      val certificate = selfSigned

      assertTrue(Certificate.RSA(certificate.blob.toByteArray) == Right(certificate))
    }
    test("issues a distinct serial number for identical input") {
      assertTrue(selfSigned.asJava.getSerialNumber != selfSigned.asJava.getSerialNumber)
    }
    test("draws a serial number RFC 5280 allows") {
      check(Gen.unit) { _ =>
        val serial = selfSigned.asJava.getSerialNumber

        assertTrue(serial.signum == 1, serial.toByteArray.length <= 20)
      }
    }
    test("registers no JVM-wide security provider") {
      selfSigned

      assertTrue(Option(Security.getProvider("BC")).isEmpty)
    }
    test("accepts only a signature algorithm that fits the key") {
      val fitting  = typeChecks("Certificate.selfSigned(keyPair, RS256, subject, notBefore, 1.day)")
      val mismatch = typeChecks("Certificate.selfSigned(aesKeyPair, RS256, subject, notBefore, 1.day)")

      assertTrue(fitting, !mismatch)
    }
  }
}
