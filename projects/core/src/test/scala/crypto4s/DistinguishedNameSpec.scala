package crypto4s

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import zio.Scope
import zio.test.*

object DistinguishedNameSpec extends ZIOSpecDefault {
  private def relativeNames(name: DistinguishedName) = X500Name.getInstance(name.asJava.getEncoded).getRDNs.toList

  private def commonNames(name: DistinguishedName) =
    X500Name.getInstance(name.asJava.getEncoded).getRDNs(BCStyle.CN).toList.map(_.getFirst.getValue.toString)

  override def spec: Spec[TestEnvironment & Scope, Any] = suiteAll("DistinguishedName") {
    suiteAll("commonName") {
      test("keeps a value containing DN syntax as a single common name") {
        val name = DistinguishedName.commonName("Acme, O=Evil+OU=Evil")

        assertTrue(
          relativeNames(name).size == 1,
          commonNames(name) == List("Acme, O=Evil+OU=Evil")
        )
      }
      test("keeps any value intact") {
        check(Gen.string) { value =>
          assertTrue(commonNames(DistinguishedName.commonName(value)) == List(value))
        }
      }
    }
  }
}
