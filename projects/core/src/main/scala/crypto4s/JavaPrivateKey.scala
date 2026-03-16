package crypto4s

import java.security.PrivateKey as JPrivateKey

private[crypto4s] case class JavaPrivateKey[Alg](
  delegate: JPrivateKey
) extends PrivateKey[Alg] {

  override def asJava: JPrivateKey = delegate
}
