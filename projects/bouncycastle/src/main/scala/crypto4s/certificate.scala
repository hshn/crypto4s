package crypto4s

import java.math.BigInteger
import java.security.Security
import java.time.Instant
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import scala.concurrent.duration.FiniteDuration

given [Alg]: Certification[Alg] = new Certification[Alg] {
  override def certificate[SigAlg](
    keyPair: KeyPair[Alg],
    subject: String,
    issuer: String,
    notBefore: Instant,
    notAfter: Instant
  )(using signing: Signing[Alg, SigAlg]): Certificate[Alg] = {

    val signer = new JcaContentSignerBuilder(signing.asJava.getAlgorithm).build(keyPair.privateKey.asJava)
    val certBuilder = new JcaX509v3CertificateBuilder(
      new X500Name(issuer),
      BigInteger.valueOf(at.toEpochMilli),
      Date.from(notBefore),
      Date.from(notAfter),
      new X500Name(subject),
      keyPair.publicKey.asJava
    )

    val bouncyCastle = "BC"
    if (Security.getProvider(bouncyCastle) == null)
      Security.addProvider(new BouncyCastleProvider())
    else
      ()

    val cert = new JcaX509CertificateConverter()
      .setProvider(bouncyCastle)
      .getCertificate(certBuilder.build(signer))

    new JavaCertificate[Alg](delegate = cert)
  }
}
