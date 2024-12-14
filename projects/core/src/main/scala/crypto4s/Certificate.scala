package crypto4s

import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate as JCertificate
import java.time.Instant
import java.util.Date

trait Certificate[Alg] {
  val publicKey: PublicKey[Alg]
  val signature: Signed[Alg, Certificate[Alg]]

  def isValid(at: Instant): Boolean

  def asJava: JCertificate
}

object Certificate {
  def make[Alg](data: Array[Byte]): Either[CertificateException, Certificate[Alg]] = try {
    val certificate = CertificateFactory
      .getInstance("X.509")
      .generateCertificate(new java.io.ByteArrayInputStream(data))
      .asInstanceOf[JCertificate]

    Right(new JavaCertificate(certificate))
  } catch {
    case e: CertificateException => Left(e)
  }
}

private[crypto4s] class JavaCertificate[Alg](
  delegate: JCertificate
) extends Certificate[Alg] {
  override val publicKey: PublicKey[Alg]                = PublicKey.fromJava(delegate.getPublicKey)
  override val signature: Signed[Alg, Certificate[Alg]] = Signed(delegate.getSignature)

  override def isValid(at: Instant): Boolean = try {
    delegate.checkValidity(Date.from(at))
    true
  } catch {
    case _: CertificateException            => false
    case _: CertificateNotYetValidException => false
  }

  override def asJava: JCertificate = delegate
}
