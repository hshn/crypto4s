package crypto4s

import crypto4s.algorithm.RSA
import crypto4s.algorithm.SHA256
import java.nio.charset.StandardCharsets.UTF_8
import java.security.cert.CertificateParsingException
import java.time.Instant
import java.util.Base64
import zio.Scope
import zio.ZIO
import zio.test.*

object CertificateSpec extends ZIOSpecDefault {
  private def base64(value: String): Array[Byte] = Base64.getDecoder.decode(value)

  // Self-signed certificate with the shape existing deployments have stored: millisecond serial, UTF8String CN, no extensions.
  private val storedCertificate = base64(
    "MIICqjCCAZKgAwIBAgIGAZktY8JLMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTI1MDkwOTA3MzIxNloXDTI2MDkwOTA3MzIxNlowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHZ3/SGNbBR2O9TvM0qLdAEki2dsDeDdxQg4oyBc/2/r4GIY5iSpvxHf1BPpjyaKcKfyWTwnsUjnZ2IyCFpxtfrIWyD1Y/KTHj9Pu6KEd+boA4TjDnA4iisbAjM2tVeBeYMLg55SdvUWtdleoKPIOtfdrl4zYerZdZh5Ysq0sccAP1zVE2TAA7+QKYs8mnAm1U3ByRYaGz0p3vFpUIU2YQUKjYCThsaSxy/VsaLxvM2JfrgWaROmstMU65jA2zWhwS2cQQ8a1Z6tzkF+fhyNzCvvPVvW/cDzaAYbAhNywwVVAepO3vzcG3IMF5dzmpSJmLprr3zsqWUFdeID9WcekPAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAK6bfHllNCrCcnav15TFgrQeqRwMp+yT4X8sghJzZkl+ohIVkRrkjhM6wrUwy/F6z145tMiFUqOOMhFeg2DbZkf5ksGdbuE67b9Jbu/WpgyA4k/MmiSGh8RS5uaMjZVTCXeA4lbzM/uAGatLyCMNmXFvcq6ZcxW8qP486Whq2fx8+Uk3AeEvZ44iKFpdHWYnDqvcs+SzfwC2ZMC5MdsJbzMbsoz3anY0+h80BYoHDxvVOwm0cLJKB9whXkWAEuXdmCUdn+a+n1qWv4bhK+pML1zNHfDEegZY68Ncme/Eo9/ttvxQ1ZqXi36b9VKoKFI0wegStZy1LnXu47xA5TsAj4k="
  )
  private val storedPublicKey = base64(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx2d/0hjWwUdjvU7zNKi3QBJItnbA3g3cUIOKMgXP9v6+BiGOYkqb8R39QT6Y8minCn8lk8J7FI52diMghacbX6yFsg9WPykx4/T7uihHfm6AOE4w5wOIorGwIzNrVXgXmDC4OeUnb1FrXZXqCjyDrX3a5eM2Hq2XWYeWLKtLHHAD9c1RNkwAO/kCmLPJpwJtVNwckWGhs9Kd7xaVCFNmEFCo2Ak4bGkscv1bGi8bzNiX64FmkTprLTFOuYwNs1ocEtnEEPGtWerc5Bfn4cjcwr7z1b1v3A82gGGwITcsMFVQHqTt783BtyDBeXc5qUiZi6a6987KllBXXiA/VnHpDwIDAQAB"
  )

  // openssl: RSA leaf CN=leaf.example.com issued by CN=ca.example.com
  private val issuedCertificate = base64(
    "MIIDBjCCAe6gAwIBAgIUNDlciPnU+TYtuLek7Cr1U6R66T8wDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwOY2EuZXhhbXBsZS5jb20wIBcNMjYxMTA3MTUyODI2WhgPMjEyNjEwMTQxNTI4MjZaMBsxGTAXBgNVBAMMEGxlYWYuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa2BzaSSx3+yDqfI/7T42QzJOwqmsq/T+i7qcPqjx9tyCiqEirntWjJUDuc5qrGo97jHheUbPAd4lJr79elfLmO8X+yUk7Bpt11sLkI6eOaGewGhp8/24ZbR6Kldm5lzY/tPdU1sWr3nAvrwZyZkikJTgRsqCGKmSMZ9Wg4rEdYxEnmK6eya8nQyRuPQdNFdSx9zJnD/eI8m/vaqXYlwlbCHD1JInpDRbO4yVGfZ86sO5ZLbmPgaMqZRCWhJeWFj37YtlShvNNKi0vVPh5rmU9gY8fe2taSNc+HebKbYyE3qOKgBGhTKUc/K3c4v41XvMiDoGUPWg1TWHcw7lJQkezAgMBAAGjQjBAMB0GA1UdDgQWBBRjPxDRLOGAfiMTar14+oIAMh/xTTAfBgNVHSMEGDAWgBQS6eHAgotptpW2FG1B0CCM2mdcdjANBgkqhkiG9w0BAQsFAAOCAQEAIlJ/a3/hr5ugZcGoa7IZF5WkDs8IwNZLF3klGEMDeW9V1rfQTEIuNRb0dBwaiOpqqGctJxQkM7azFG+Vt0E9RQpNohq+jeHYJYCVucn9G/g6hd4l+Wn0IdLH0mZqOBE1YgB2BLyDVfkjIjsJVTJrVL1hsvy3Ct8skMFbgPL3Ym8ej/Q7UmKLGLuN9V9jWQR05qmqGNlci+bW/vvUD5JLBh7Wu7l8yzzNEEOrsukIJpZfNymch+GVp5kx+tHDI/bd9YZAYH/8mqAgZuFUQ7fTJUTNGuH3vsu69dSck+lqqEuQ9WcNx2nEOyH6kjE58iHu/P1Fg4Ir7VSi/hCzgdz5Sg=="
  )

  // openssl: self-signed EC P-256
  private val ecCertificate = base64(
    "MIIBijCCAS+gAwIBAgIUP63OL1X5gEueDd0yXO1uwl25hZcwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOZWMuZXhhbXBsZS5jb20wIBcNMjYxMTA3MTUyODI2WhgPMjEyNjEwMTQxNTI4MjZaMBkxFzAVBgNVBAMMDmVjLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK+AzG/otFPiPaEBX5tpGprZJYwwGPCWzKMYgVx4krRDEm8UsDhBFfJeG/v5MLagm5RGGSFnba9O38riFjk1PaKNTMFEwHQYDVR0OBBYEFOTPAsbAmYWEzQWfiJQW0n9mcTNKMB8GA1UdIwQYMBaAFOTPAsbAmYWEzQWfiJQW0n9mcTNKMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAIn9AB6cdPPKl6Tq5Wj0EpeffPirt7UldJQQVRIOIKfJAiEAkUDrkuzGDKALemSswEFKCSjh1VXJGKTIt/YkzMPoB2w="
  )

  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("Certificate") {
    suiteAll("RSA") {
      test("reads the fields of a stored certificate") {
        for {
          certificate <- ZIO.fromEither(Certificate.RSA(storedCertificate))
          publicKey   <- ZIO.fromEither(PublicKey.RSA(storedPublicKey))
        } yield assertTrue(
          certificate.publicKey == publicKey,
          certificate.subject == DistinguishedName.commonName("example.com"),
          certificate.notBefore == Instant.parse("2025-09-09T07:32:16Z"),
          certificate.notAfter == Instant.parse("2026-09-09T07:32:16Z")
        )
      }
      test("tells the subject from the issuer") {
        for {
          certificate <- ZIO.fromEither(Certificate.RSA(issuedCertificate))
        } yield assertTrue(
          certificate.subject == DistinguishedName.commonName("leaf.example.com"),
          certificate.issuer == DistinguishedName.commonName("ca.example.com")
        )
      }
      test("rejects a certificate for a non-RSA key") {
        assertTrue(Certificate.RSA(ecCertificate).is(_.left.subtype[UnexpectedCertificateKey]).actual == "EC")
      }
      test("rejects a truncated certificate") {
        assertTrue(Certificate.RSA(storedCertificate.dropRight(1)).isLeft)
      }
      test("rejects bytes trailing the certificate") {
        assertTrue(Certificate.RSA(storedCertificate :+ 0.toByte).is(_.left).isInstanceOf[CertificateParsingException])
      }
      test("rejects a PEM-encoded certificate") {
        val pem = s"-----BEGIN CERTIFICATE-----\n${Base64.getMimeEncoder.encodeToString(storedCertificate)}\n-----END CERTIFICATE-----\n"

        assertTrue(Certificate.RSA(pem.getBytes(UTF_8)).is(_.left).isInstanceOf[CertificateParsingException])
      }
      test("rejects bytes that are not a certificate") {
        check(Gen.listOf(Gen.byte)) { bytes =>
          assertTrue(Certificate.RSA(bytes.toArray).isLeft)
        }
      }
    }
    suiteAll("encoding") {
      test("blob is the DER the certificate was read from") {
        for {
          certificate <- ZIO.fromEither(Certificate.RSA(storedCertificate))
        } yield assertTrue(certificate.blob == Blob(storedCertificate))
      }
      test("thumbprint is the digest of the DER") {
        for {
          certificate <- ZIO.fromEither(Certificate.RSA(storedCertificate))
        } yield assertTrue(
          // openssl x509 -fingerprint -sha256
          certificate.hashed[SHA256].hash.toHexString == "b39632f1900b851f76496f00c4ebdc5b3c393532c6cb938c9e7427e1160c8d7c"
        )
      }
      test("deserializes from DER") {
        assertTrue(storedCertificate.deserialize[Certificate[RSA]] == Certificate.RSA(storedCertificate))
      }
      test("keeps the reason a certificate could not be deserialized") {
        assertTrue(
          ecCertificate.deserialize[Certificate[RSA]].is(_.left).getCause.is(_.subtype[UnexpectedCertificateKey]).actual == "EC"
        )
      }
    }
  }
}
