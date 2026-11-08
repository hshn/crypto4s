package crypto4s

import crypto4s.algorithm.RS256
import crypto4s.algorithm.RSA
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

trait CertificateSigning[SignAlg, KeyAlg] {
  def contentSigner(key: PrivateKey[KeyAlg]): ContentSigner
}

object CertificateSigning {
  given CertificateSigning[RS256, RSA] = key => new JcaContentSignerBuilder("SHA256withRSA").build(key.asJava)
}
