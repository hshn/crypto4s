package crypto4s

import java.math.BigInteger
import java.security.SecureRandom
import java.time.Instant
import java.util.Date
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import scala.concurrent.duration.FiniteDuration
import scala.jdk.DurationConverters.*

private val secureRandom = new SecureRandom()

// RFC 5280 section 4.1.2.2: a positive integer of at most 20 octets, so 159 bits leave the sign bit clear
private def randomSerialNumber(): BigInteger = new BigInteger(159, secureRandom).setBit(0)

extension (certificate: Certificate.type) {
  def selfSigned[SignAlg, KeyAlg](
    keyPair: KeyPair[KeyAlg],
    algorithm: SignAlg,
    subject: DistinguishedName,
    notBefore: Instant,
    ttl: FiniteDuration
  )(using signing: CertificateSigning[SignAlg, KeyAlg]): Certificate[KeyAlg] = {
    val signed = new JcaX509v3CertificateBuilder(
      subject.asJava,
      randomSerialNumber(),
      Date.from(notBefore),
      Date.from(notBefore.plus(ttl.toJava)),
      subject.asJava,
      keyPair.publicKey.asJava
    ).build(signing.contentSigner(keyPair.privateKey))

    Certificate(new JcaX509CertificateConverter().getCertificate(signed))
  }
}
