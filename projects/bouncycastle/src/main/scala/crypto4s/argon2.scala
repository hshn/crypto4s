package crypto4s

import crypto4s.algorithm.Argon2

given Argon2Hashing = Argon2Hashing(`type` = Argon2.Type.Argon2id)
