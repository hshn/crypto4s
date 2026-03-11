package crypto4s

import crypto4s.algorithm.HmacSHA1
import crypto4s.algorithm.HmacSHA256

trait Macing[Alg] { self =>
  type Result[A] <: Maced[Alg, A]

  def mac[A](key: MacSecretKey[Alg], a: A)(using Blob[A]): Result[A]
}

object Macing {
  def apply[Alg](using macing: Macing[Alg]): Macing[Alg] = macing

  given Macing[HmacSHA1]   = HmacSHA1JavaMacing
  given Macing[HmacSHA256] = HmacSHA256JavaMacing
}

object MacingExtension extends MacingExtension
trait MacingExtension {
  extension [A](a: A) {
    def maced[Alg](key: MacSecretKey[Alg])(using macing: Macing[Alg], blob: Blob[A]): macing.Result[A] = macing.mac(key, a)
  }
}
