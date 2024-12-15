package crypto4s.bouncycastle

import crypto4s.PrivateKey
import crypto4s.Signing
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.ContentSigner

class ContentSignerImpl[Alg, KeyAlg](
  privateKey: PrivateKey[KeyAlg]
)(using Signing[Alg, KeyAlg])
    extends ContentSigner {
  private val output = new ByteArrayOutputStream()

  override def getAlgorithmIdentifier: AlgorithmIdentifier =
    AlgorithmIdentifier.getInstance(summon[Signing[Alg, KeyAlg]].asJava.getAlgorithm)

  override def getOutputStream: OutputStream = output

  override def getSignature: Array[Byte] = {
    privateKey.sign(output.toByteArray).underlying
  }
}
