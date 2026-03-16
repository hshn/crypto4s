package crypto4s

sealed abstract class DeserializationException(message: String, cause: Exception | Null = null)
    extends Exception(message, cause)

object DeserializationException {
  final class InvalidKeyBytes(keyType: String, cause: Exception)
      extends DeserializationException(s"Failed to deserialize $keyType", cause)
}
