package cipher4s

import cipher4s.Algorithm.Argon2.Type
import cipher4s.implicits.*
import java.security.MessageDigest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

trait Hashing[Alg, A] { self =>
  type Result <: Hashed[Alg, A]

  def hash(a: A)(using Blob[A]): Result
}

object Hashing {
  given [A]: Hashing[Algorithm.SHA1, A] = new Hashing[Algorithm.SHA1, A] {
    override type Result = Hashed.SHA1[A]
    override def hash(a: A)(using Blob[A]): Hashed.SHA1[A] = {
      val hash = MessageDigest
        .getInstance("SHA-1")
        .digest(a.blob)

      Hashed.SHA1(hash = hash)
    }
  }

  given [A]: Hashing[Algorithm.SHA256, A] = new Hashing[Algorithm.SHA256, A] {
    override type Result = Hashed.SHA256[A]
    override def hash(a: A)(using Blob[A]): Hashed.SHA256[A] = {
      val hash = MessageDigest
        .getInstance("SHA-256")
        .digest(a.blob)

      Hashed.SHA256(hash = hash)
    }
  }

  def Argon2i[A]: Argon2Hashing[A]  = Argon2[A](`type` = Type.Argon2i)
  def Argon2d[A]: Argon2Hashing[A]  = Argon2[A](`type` = Type.Argon2d)
  def Argon2id[A]: Argon2Hashing[A] = Argon2[A](`type` = Type.Argon2id)

  private def Argon2[A](
    `type`: Algorithm.Argon2.Type = Type.Argon2id
  ): Argon2Hashing[A] = new Argon2Hashing[A](
    `type` = `type`,
    version = Algorithm.Argon2.Version.V13,
    salt = None,
    memory = MemorySize.mb(64),
    iterations = 2,
    length = 32,
    parallelism = 1
  )
}

case class Argon2Hashing[A](
  `type`: Algorithm.Argon2.Type,
  version: Algorithm.Argon2.Version,
  salt: Option[Array[Byte]],
  memory: MemorySize,
  iterations: Int,
  length: Int,
  parallelism: Int
) extends Hashing[Algorithm.Argon2, A] {
  override type Result = Hashed.Argon2[A]

  def withVersion(version: Algorithm.Argon2.Version): Argon2Hashing[A] = copy(version = version)
  def withSalt(salt: Array[Byte]): Argon2Hashing[A]                    = copy(salt = Some(salt))
  def withMemory(memory: MemorySize): Argon2Hashing[A]                 = copy(memory = memory)
  def withIterations(iterations: Int): Argon2Hashing[A]                = copy(iterations = iterations)
  def withLength(length: Int): Argon2Hashing[A]                        = copy(length = length)
  def withParallelism(parallelism: Int): Argon2Hashing[A]              = copy(parallelism = parallelism)

  override def hash(a: A)(using Blob[A]): Hashed.Argon2[A] = {
    val parameters = new Argon2Parameters.Builder(`type` match {
      case Algorithm.Argon2.Type.Argon2d  => Argon2Parameters.ARGON2_d
      case Algorithm.Argon2.Type.Argon2i  => Argon2Parameters.ARGON2_i
      case Algorithm.Argon2.Type.Argon2id => Argon2Parameters.ARGON2_id
    })
      .withVersion(version match {
        case Algorithm.Argon2.Version.V10 => Argon2Parameters.ARGON2_VERSION_10
        case Algorithm.Argon2.Version.V13 => Argon2Parameters.ARGON2_VERSION_13
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

    Hashed.Argon2(
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

trait HashingExtension {
  extension [A](a: A) {
    def toHashed[Alg](using hashing: Hashing[Alg, A], blob: Blob[A]): hashing.Result = hashing.hash(a)
  }
}
