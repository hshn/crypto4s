package crypto4s

import crypto4s.algorithm.Argon2

given [A]: Argon2Hashing[A] = Argon2Hashing[A](`type` = Argon2.Type.Argon2id)
