package crypto4s

import crypto4s.algorithm.AES
import crypto4s.algorithm.AESGCM
import crypto4s.algorithm.RSA
import crypto4s.algorithm.RSAOAEP256
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

trait Encrypting[Alg, Key] {

  /** Encrypts `data` bound to `context`. The context is authenticated but not stored in the ciphertext, so decryption needs the same
    * context again. An empty context is the same as no context.
    */
  def encrypt(key: Key, data: Array[Byte], context: Array[Byte]): Array[Byte]
  def encrypt(key: Key, data: Array[Byte]): Array[Byte] = encrypt(key, data, Array.emptyByteArray)
  def encrypt[A, C](key: Key, a: A, context: C)(using encoder: BlobEncoder[A], contextEncoder: BlobEncoder[C]): Encrypted[Alg, A] =
    Encrypted(Blob.wrap(encrypt(key, encoder.encode(a).toByteArray, contextEncoder.encode(context).toByteArray)))
  def encrypt[A](key: Key, a: A)(using encoder: BlobEncoder[A]): Encrypted[Alg, A] =
    Encrypted(Blob.wrap(encrypt(key, encoder.encode(a).toByteArray)))
}

object Encrypting {
  private val secureRandom = new SecureRandom()

  given Encrypting[AESGCM, SecretKey[AES]] with {
    override def encrypt(key: SecretKey[AES], data: Array[Byte], context: Array[Byte]): Array[Byte] = {
      val iv = new Array[Byte](AESGCM.ivLength)
      secureRandom.nextBytes(iv)
      val cipher = Cipher.getInstance(AESGCM.transformation)
      cipher.init(Cipher.ENCRYPT_MODE, key.asJava, new GCMParameterSpec(AESGCM.tagLength, iv))
      cipher.updateAAD(context)
      val ciphertext = cipher.doFinal(data)
      iv ++ ciphertext
    }
  }

  given Encrypting[RSAOAEP256, PublicKey[RSA]] with {
    override def encrypt(key: PublicKey[RSA], data: Array[Byte], context: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance(RSAOAEP256.transformation)
      cipher.init(Cipher.ENCRYPT_MODE, key.asJava, RSAOAEP256.oaepParameters(label = context))
      cipher.doFinal(data)
    }
  }
}
