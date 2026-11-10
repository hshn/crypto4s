# Changelog

## [0.8.0](https://github.com/hshn/crypto4s/compare/v0.7.0...v0.8.0) (2026-11-10)


### ⚠ BREAKING CHANGES

* bind ciphertext to a caller-supplied context ([#164](https://github.com/hshn/crypto4s/issues/164))

### Features

* bind ciphertext to a caller-supplied context ([#164](https://github.com/hshn/crypto4s/issues/164)) ([7426923](https://github.com/hshn/crypto4s/commit/742692394586a62993a6c68a5436c9c5107ca072))

## [0.7.0](https://github.com/hshn/crypto4s/compare/v0.6.0...v0.7.0) (2026-11-08)


### ⚠ BREAKING CHANGES

* drop BouncyCastle from crypto4s-core's runtime dependencies ([#161](https://github.com/hshn/crypto4s/issues/161))
* tag ciphertexts with the encryption scheme, not the key type ([#157](https://github.com/hshn/crypto4s/issues/157))
* stop MemorySize from overflowing on large sizes ([#158](https://github.com/hshn/crypto4s/issues/158))
* apply Argon2 salt and add opt-in random salt per hash ([#154](https://github.com/hshn/crypto4s/issues/154))

### Features

* add javax.crypto.Mac support (HmacSHA1, HmacSHA256) ([#102](https://github.com/hshn/crypto4s/issues/102)) ([61ec066](https://github.com/hshn/crypto4s/commit/61ec0664b8265dab3206065c48f71d815df81a95))
* apply Argon2 salt and add opt-in random salt per hash ([#154](https://github.com/hshn/crypto4s/issues/154)) ([8114fa0](https://github.com/hshn/crypto4s/commit/8114fa04db280b9d30c48747c1c2fd56412f7f40))
* encrypt RSA with OAEP SHA-256 instead of PKCS[#1](https://github.com/hshn/crypto4s/issues/1) v1.5 ([#153](https://github.com/hshn/crypto4s/issues/153)) ([33b674a](https://github.com/hshn/crypto4s/commit/33b674a4b4a8445e8f7197f4ea3507aa56e402c7))
* read RSA X.509 certificates and create self-signed ones ([#160](https://github.com/hshn/crypto4s/issues/160)) ([570c577](https://github.com/hshn/crypto4s/commit/570c57760f7b6d3a142a7f210d861fc9cdf7d7f4))
* tag ciphertexts with the encryption scheme, not the key type ([#157](https://github.com/hshn/crypto4s/issues/157)) ([759c86e](https://github.com/hshn/crypto4s/commit/759c86eda931eae893c84713a7babf49f6474628))
* use AES-GCM as the default AES encryption mode ([#113](https://github.com/hshn/crypto4s/issues/113)) ([7bf977a](https://github.com/hshn/crypto4s/commit/7bf977ae9fecbd84fb09a4cf7c8740aa987efb96))


### Bug Fixes

* drop BouncyCastle from crypto4s-core's runtime dependencies ([#161](https://github.com/hshn/crypto4s/issues/161)) ([2fa329c](https://github.com/hshn/crypto4s/commit/2fa329c5c17538c438dfadd0c4ae6c14e7908456))
* stop MemorySize from overflowing on large sizes ([#158](https://github.com/hshn/crypto4s/issues/158)) ([f505ad7](https://github.com/hshn/crypto4s/commit/f505ad79d98dd3b1880b61fba4a5572746b3859a))
* use explicit RSA/ECB/PKCS1Padding cipher transformation ([#110](https://github.com/hshn/crypto4s/issues/110)) ([f11d1f9](https://github.com/hshn/crypto4s/commit/f11d1f9cd5dd42177b3c4a512d6c8d33553c0c07))
