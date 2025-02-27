package crypto4s

import crypto4s.algorithm.Argon2

case class Argon2Hash[A](
  hash: Array[Byte],
  `type`: Argon2.Type,
  version: Argon2.Version,
  salt: Option[Array[Byte]],
  memory: MemorySize,
  iterations: Int,
  length: Int,
  parallelism: Int
) extends Hashed[Argon2, A] {
  override def verify(of: A)(using Hashing[Argon2], Blob[A]): Boolean = {
    val hashing = Argon2Hashing(
      `type` = `type`,
      version = version,
      salt = salt,
      memory = memory,
      iterations = iterations,
      length = length,
      parallelism = parallelism
    )

    verify(hashing.hash(of))
  }
}
