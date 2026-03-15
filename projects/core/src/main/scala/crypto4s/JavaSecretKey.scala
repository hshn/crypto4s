package crypto4s

import javax.crypto.SecretKey as JSecretKey

private[crypto4s] class JavaSecretKey[Alg](
  delegate: JSecretKey
) extends SecretKey[Alg] {

  override def asJava: JSecretKey = delegate
}
