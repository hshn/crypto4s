package crypto4s

import crypto4s.MemorySize
import crypto4s.algorithm.Argon2

given [A]: Argon2Hashing[A] = Argon2id[A]

def Argon2i[A]: Argon2Hashing[A]  = Argon2Hashing[A](`type` = Argon2.Type.Argon2i)
def Argon2d[A]: Argon2Hashing[A]  = Argon2Hashing[A](`type` = Argon2.Type.Argon2d)
def Argon2id[A]: Argon2Hashing[A] = Argon2Hashing[A](`type` = Argon2.Type.Argon2id)
