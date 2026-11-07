package crypto4s

import crypto4s.algorithm.Argon2

case class Argon2Hash[A](
  hash: Blob,
  parameters: Argon2.Parameters
) extends Hashed[Argon2, A] {
  override def verify(of: A)(using BlobEncoder[A]): Boolean = verify(parameters.hash(of.blob.toByteArray))
}
