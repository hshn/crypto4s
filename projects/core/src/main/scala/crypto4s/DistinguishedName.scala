package crypto4s

import javax.naming.ldap.Rdn
import javax.security.auth.x500.X500Principal

final case class DistinguishedName private[crypto4s] (asJava: X500Principal)

object DistinguishedName {
  def commonName(value: String): DistinguishedName = DistinguishedName(new X500Principal(s"CN=${Rdn.escapeValue(value)}"))
}
