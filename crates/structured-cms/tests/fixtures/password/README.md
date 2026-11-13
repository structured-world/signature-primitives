# Password-protection fixtures

OpenSSL 4.0.3 generated these disposable P-256 keys and their self-signed
certificate. The public test password is `fixture`. Never deploy these keys.

- PKCS#8: `openssl pkcs8 -topk8` with `-nocrypt`,
  `-v2 aes-256-cbc -iter 8`, or
  `-scrypt -scrypt_N 16 -scrypt_r 2 -scrypt_p 2`, with DER output.
- PKCS#12: `openssl pkcs12 -export -iter 8` with default algorithms, with
  `-pbmac1_pbkdf2`, and with
  `-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES`.
