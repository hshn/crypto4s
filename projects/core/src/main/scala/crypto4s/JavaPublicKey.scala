package crypto4s

import java.security.PublicKey as JPublicKey

private[crypto4s] case class JavaPublicKey[Alg](
  delegate: JPublicKey
) extends PublicKey[Alg] {

  override def asJava: JPublicKey = delegate
}
