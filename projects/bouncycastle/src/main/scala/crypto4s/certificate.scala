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

extension [Alg](keyPair: KeyPair[Alg]) {
  def makeCertificate[SigAlg](
    ttl: FiniteDuration,
    subjectDN: String,
    issuerDN: String,
    at: Instant
  )(using Signing[Alg, SigAlg]): JavaCertificate[Alg] = {
    val signer = new JcaContentSignerBuilder(
      summon[Signing[Alg, SigAlg]].asJava.getAlgorithm
    ).build(keyPair.privateKey.asJava)

    val certBuilder = new JcaX509v3CertificateBuilder(
      new X500Name(s"CN=$issuerDN"),
      BigInteger.valueOf(at.toEpochMilli),
      Date.from(at),
      Date.from(at.plusSeconds(ttl.toSeconds)),
      new X500Name(s"CN=$subjectDN"),
      keyPair.publicKey.asJava
    )

    Security.addProvider(new BouncyCastleProvider())

    val bouncyCastle = "BC"
    val cert = new JcaX509CertificateConverter()
      .setProvider(bouncyCastle)
      .getCertificate(certBuilder.build(signer))

    new JavaCertificate[Alg](delegate = cert)
  }
}
