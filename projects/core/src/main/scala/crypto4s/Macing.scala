package crypto4s

import crypto4s.algorithm.HmacSHA1
import crypto4s.algorithm.HmacSHA256

trait Macing[Alg] { self =>
  type Result[A] <: Maced[Alg, A]

  def mac[A](key: MacKey[Alg], a: A)(using BlobEncoder[A]): Result[A]
}

object Macing {
  def apply[Alg](using macing: Macing[Alg]): Macing[Alg] = macing

  given Macing[HmacSHA1]   = HmacSHA1JavaMacing
  given Macing[HmacSHA256] = HmacSHA256JavaMacing
}

object MacingExtension extends MacingExtension
trait MacingExtension {
  extension [A](a: A) {
    def maced[Alg](key: MacKey[Alg])(using macing: Macing[Alg], encoder: BlobEncoder[A]): macing.Result[A] = macing.mac(key, a)
  }
}
