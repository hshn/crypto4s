package crypto4s

import java.time.Instant
import scala.concurrent.duration.FiniteDuration

trait Certification[Alg] {
  def certificate[SigAlg](
    keyPair: KeyPair[Alg],
    subject: String,
    issuer: String,
    ttl: FiniteDuration,
    at: Instant
  )(using signing: Signing[Alg, SigAlg]): Certificate[Alg] = certificate(
    keyPair = keyPair,
    subject = subject,
    issuer = issuer,
    notBefore = at,
    notAfter = at.plusSeconds(ttl.toSeconds)
  )

  def certificate[SigAlg](
    keyPair: KeyPair[Alg],
    subject: String,
    issuer: String,
    notBefore: Instant,
    notAfter: Instant
  )(using signing: Signing[Alg, SigAlg]): Certificate[Alg]
}
