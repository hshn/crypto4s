package crypto4s

import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant

final case class Certificate[Alg] private[crypto4s] (asJava: X509Certificate) {
  def publicKey: PublicKey[Alg]  = PublicKey.fromJava(asJava.getPublicKey)
  def subject: DistinguishedName = DistinguishedName(asJava.getSubjectX500Principal)
  def issuer: DistinguishedName  = DistinguishedName(asJava.getIssuerX500Principal)
  def notBefore: Instant         = asJava.getNotBefore.toInstant
  def notAfter: Instant          = asJava.getNotAfter.toInstant
}

object Certificate {
  def RSA(der: Array[Byte]): Either[CertificateException, Certificate[algorithm.RSA]] = try {
    val factory     = CertificateFactory.getInstance("X.509")
    val certificate = factory.generateCertificate(new ByteArrayInputStream(der)).asInstanceOf[X509Certificate]
    val key         = certificate.getPublicKey.getAlgorithm

    Either.cond(key == "RSA", Certificate(certificate), new UnexpectedCertificateKey(expected = "RSA", actual = key))
  } catch {
    case e: CertificateException => Left(e)
  }
}

final class UnexpectedCertificateKey(val expected: String, val actual: String)
  extends CertificateException(s"Expected a certificate for a $expected key but got $actual")
