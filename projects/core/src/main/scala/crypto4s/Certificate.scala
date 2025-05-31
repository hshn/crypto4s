package crypto4s

import java.io.ByteArrayInputStream
import java.security.Principal
import java.security.SignatureException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate as JCertificate
import java.time.Instant
import java.util.Date
import scala.concurrent.duration.FiniteDuration

trait Certificate[Alg] {
  val publicKey: PublicKey[Alg]
  val signature: Signed[Alg, Certificate[Alg]]

  def issuer: Principal
  def subject: Principal

  def verify(publicKey: PublicKey[Alg]): Either[SignatureException, Unit]
  def validate(at: Instant): Either[CertificateExpiredException | CertificateNotYetValidException, Unit]

  def asJava: JCertificate
}

object Certificate {
  def make[KeyAlg, SigAlg](
    keyPair: KeyPair[KeyAlg],
    ttl: FiniteDuration,
    subjectDN: String,
    issuerDN: String,
    at: Instant
  )(using Signing[SigAlg, KeyAlg]) = {
    ???
  }

  def make[Alg](data: Array[Byte]): Either[CertificateException, Certificate[Alg]] = try {
    val certificate = CertificateFactory
      .getInstance("X.509")
      .generateCertificate(new ByteArrayInputStream(data))
      .asInstanceOf[JCertificate]

    Right(new JavaCertificate(certificate))
  } catch {
    case e: CertificateException => Left(e)
  }

  given [Alg]: Blob[Certificate[Alg]] with {
    override def asBlob(a: Certificate[Alg]): Array[Byte] = a.asJava.getEncoded
  }
}

private[crypto4s] class JavaCertificate[Alg](
  delegate: JCertificate
) extends Certificate[Alg] {
  override val publicKey: PublicKey[Alg]                = PublicKey.fromJava(delegate.getPublicKey)
  override val signature: Signed[Alg, Certificate[Alg]] = Signed(delegate.getSignature)
  override def issuer: Principal                        = delegate.getIssuerX500Principal
  override def subject: Principal                       = delegate.getSubjectX500Principal

  override def verify(publicKey: PublicKey[Alg]): Either[SignatureException, Unit] = try {
    delegate.verify(publicKey.asJava)

    Right(())
  } catch {
    case e: SignatureException => Left(e)
  }

  override def validate(at: Instant): Either[CertificateExpiredException | CertificateNotYetValidException, Unit] = try {
    delegate.checkValidity(Date.from(at))
    Right(())
  } catch {
    case e: CertificateExpiredException     => Left(e)
    case e: CertificateNotYetValidException => Left(e)
  }

  override def asJava: JCertificate = delegate
}
