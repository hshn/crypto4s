package crypto4s

import crypto4s.algorithm.Argon2
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

case class Argon2Hashing(
  `type`: Argon2.Type,
  version: Argon2.Version,
  salt: Option[Array[Byte]],
  memory: MemorySize,
  iterations: Int,
  length: Int,
  parallelism: Int
) extends Hashing[Argon2] {
  override type Result[A] = Argon2Hash[A]

  def withVersion(version: Argon2.Version): Argon2Hashing = copy(version = version)
  def withSalt(salt: Array[Byte]): Argon2Hashing          = copy(salt = Some(salt))
  def withMemory(memory: MemorySize): Argon2Hashing       = copy(memory = memory)
  def withIterations(iterations: Int): Argon2Hashing      = copy(iterations = iterations)
  def withLength(length: Int): Argon2Hashing              = copy(length = length)
  def withParallelism(parallelism: Int): Argon2Hashing    = copy(parallelism = parallelism)

  override def hash[A](a: A)(using Blob[A]): Argon2Hash[A] = {
    val parameters = new Argon2Parameters.Builder(`type` match {
      case Argon2.Type.Argon2d  => Argon2Parameters.ARGON2_d
      case Argon2.Type.Argon2i  => Argon2Parameters.ARGON2_i
      case Argon2.Type.Argon2id => Argon2Parameters.ARGON2_id
    })
      .withVersion(version match {
        case Argon2.Version.V10 => Argon2Parameters.ARGON2_VERSION_10
        case Argon2.Version.V13 => Argon2Parameters.ARGON2_VERSION_13
      })
      .withMemoryAsKB(memory.toKb)
      .withIterations(iterations)
      .withParallelism(parallelism)
      .withParallelism(parallelism)

    val generator = new Argon2BytesGenerator()
    generator.init(parameters.build())

    val hash = new Array[Byte](length)

    generator.generateBytes(
      a.blob,
      hash,
      0,
      hash.length
    )

    Argon2Hash(
      hash = hash,
      `type` = `type`,
      version = version,
      salt = salt,
      memory = memory,
      iterations = iterations,
      length = length,
      parallelism = parallelism
    )
  }
}

object Argon2Hashing {
  def apply(`type`: Argon2.Type = Argon2.Type.Argon2id): Argon2Hashing = new Argon2Hashing(
    `type` = `type`,
    version = Argon2.Version.V13,
    salt = None,
    memory = MemorySize.mb(64),
    iterations = 2,
    length = 32,
    parallelism = 1
  )
}
