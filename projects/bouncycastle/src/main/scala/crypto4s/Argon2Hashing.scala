package crypto4s

import crypto4s.algorithm.Argon2

case class Argon2Hashing(
  `type`: Argon2.Type,
  version: Argon2.Version,
  salt: Argon2.SaltSource,
  memory: MemorySize,
  iterations: Int,
  length: Int,
  parallelism: Int
) extends Hashing[Argon2] {
  override type Result[A] = Argon2Hash[A]

  def withVersion(version: Argon2.Version): Argon2Hashing = copy(version = version)
  def withSalt(salt: Array[Byte]): Argon2Hashing          = copy(salt = Argon2.SaltSource.Fixed(salt))
  def withRandomSalt: Argon2Hashing                       = copy(salt = Argon2.SaltSource.Random)
  def withMemory(memory: MemorySize): Argon2Hashing       = copy(memory = memory)
  def withIterations(iterations: Int): Argon2Hashing      = copy(iterations = iterations)
  def withLength(length: Int): Argon2Hashing              = copy(length = length)
  def withParallelism(parallelism: Int): Argon2Hashing    = copy(parallelism = parallelism)

  override def hash[A](a: A)(using BlobEncoder[A]): Argon2Hash[A] = {
    val parameters = Argon2.Parameters(
      `type` = `type`,
      version = version,
      salt = salt.draw(),
      memory = memory,
      iterations = iterations,
      length = length,
      parallelism = parallelism
    )

    Argon2Hash(hash = parameters.hash(a.blob.toByteArray), parameters = parameters)
  }
}

object Argon2Hashing {
  def apply(`type`: Argon2.Type = Argon2.Type.Argon2id): Argon2Hashing = new Argon2Hashing(
    `type` = `type`,
    version = Argon2.Version.V13,
    salt = Argon2.SaltSource.Unsalted,
    memory = MemorySize.mb(64),
    iterations = 2,
    length = 32,
    parallelism = 1
  )
}
