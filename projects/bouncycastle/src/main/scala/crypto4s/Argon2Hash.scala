package crypto4s

import crypto4s.Hashed
import crypto4s.MemorySize
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
) extends Hashed[Argon2, A]
