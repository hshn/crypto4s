package crypto4s

import crypto4s.Blob
import crypto4s.Hashing
import crypto4s.MemorySize
import crypto4s.algorithm.Argon2
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

case class Argon2Hashing[A](
  `type`: Argon2.Type,
  version: Argon2.Version,
  salt: Option[Array[Byte]],
  memory: MemorySize,
  iterations: Int,
  length: Int,
  parallelism: Int
) extends Hashing[Argon2, A] {
  override type Result = Argon2Hash[A]

  def withVersion(version: Argon2.Version): Argon2Hashing[A] = copy(version = version)
  def withSalt(salt: Array[Byte]): Argon2Hashing[A]          = copy(salt = Some(salt))
  def withMemory(memory: MemorySize): Argon2Hashing[A]       = copy(memory = memory)
  def withIterations(iterations: Int): Argon2Hashing[A]      = copy(iterations = iterations)
  def withLength(length: Int): Argon2Hashing[A]              = copy(length = length)
  def withParallelism(parallelism: Int): Argon2Hashing[A]    = copy(parallelism = parallelism)

  override def hash(a: A)(using Blob[A]): Argon2Hash[A] = {
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
  def apply[A](`type`: Argon2.Type = Argon2.Type.Argon2id): Argon2Hashing[A] = new Argon2Hashing[A](
    `type` = `type`,
    version = Argon2.Version.V13,
    salt = None,
    memory = MemorySize.mb(64),
    iterations = 2,
    length = 32,
    parallelism = 1
  )
}
