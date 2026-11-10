package crypto4s.algorithm

import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

type RSA = RSA.type
case object RSA

// encryption algorithms
type RSAOAEP256 = RSAOAEP256.type
case object RSAOAEP256 {
  private[crypto4s] val transformation: String                                = "RSA/ECB/OAEPPadding"
  private[crypto4s] def oaepParameters(label: Array[Byte]): OAEPParameterSpec =
    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, new PSource.PSpecified(label))
}

type AES = AES.type
case object AES

type AESGCM = AESGCM.type
case object AESGCM {
  private[crypto4s] val transformation: String = "AES/GCM/NoPadding"
  private[crypto4s] val ivLength: Int          = 12
  private[crypto4s] val tagLength: Int         = 128
}

type SHA1 = SHA1.type
case object SHA1

type SHA256 = SHA256.type
case object SHA256

// signing algorithms
type RS256 = RS256.type
case object RS256 {
  val signatureAlgorithm: String = "SHA256withRSA"
}

// mac algorithms
type HmacSHA1 = HmacSHA1.type
case object HmacSHA1

type HmacSHA256 = HmacSHA256.type
case object HmacSHA256
