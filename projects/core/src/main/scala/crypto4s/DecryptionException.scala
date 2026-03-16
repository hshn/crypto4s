package crypto4s

sealed abstract class DecryptionException(message: String, cause: Exception | Null)
    extends Exception(message, cause)

object DecryptionException {
  final class IntegrityCheckFailed(cause: Exception)
      extends DecryptionException("Decryption integrity check failed", cause)

  final class InvalidCiphertext(message: String, cause: Exception | Null = null)
      extends DecryptionException(message, cause)
}
