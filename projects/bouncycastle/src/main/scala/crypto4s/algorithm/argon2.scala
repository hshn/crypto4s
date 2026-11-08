package crypto4s.algorithm

import crypto4s.Blob
import crypto4s.MemorySize
import java.security.SecureRandom
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

type Argon2 = Argon2.type
case object Argon2 {
  enum Type {
    case Argon2i, Argon2d, Argon2id
  }
  enum Version {
    case V10, V13
  }

  enum SaltSource {
    case Unsalted
    case Fixed(salt: Blob)
    case Random

    private[crypto4s] def draw(): Option[Blob] = this match {
      case Unsalted    => None
      case Fixed(salt) => Some(salt)
      case Random      =>
        val salt = new Array[Byte](RandomSaltLength)
        secureRandom.nextBytes(salt)
        Some(Blob.wrap(salt))
    }
  }

  // RFC 9106 section 4: a 128-bit salt is sufficient for all applications
  private val RandomSaltLength = 16
  private val secureRandom     = new SecureRandom()

  case class Parameters(
    `type`: Type,
    version: Version,
    salt: Option[Blob],
    memory: MemorySize,
    iterations: Int,
    length: Int,
    parallelism: Int
  ) {
    private[crypto4s] def hash(input: Array[Byte]): Blob = {
      val parameters = new Argon2Parameters.Builder(`type` match {
        case Type.Argon2d  => Argon2Parameters.ARGON2_d
        case Type.Argon2i  => Argon2Parameters.ARGON2_i
        case Type.Argon2id => Argon2Parameters.ARGON2_id
      })
        .withVersion(version match {
          case Version.V10 => Argon2Parameters.ARGON2_VERSION_10
          case Version.V13 => Argon2Parameters.ARGON2_VERSION_13
        })
        .withMemoryAsKB(memoryInKiB)
        .withIterations(iterations)
        .withParallelism(parallelism)

      salt.foreach(salt => parameters.withSalt(salt.toByteArray))

      val generator = new Argon2BytesGenerator()
      generator.init(parameters.build())

      val hash = new Array[Byte](length)

      generator.generateBytes(input, hash, 0, hash.length)

      Blob.wrap(hash)
    }

    private def memoryInKiB: Int = {
      require(
        memory.bytes % 1024 == 0 && memory.toKb <= Int.MaxValue,
        s"Argon2 memory must be a whole number of KiB up to ${Int.MaxValue} KiB, but was ${memory.bytes} bytes"
      )
      memory.toKb.toInt
    }
  }
}
