# Public DH test key

These synthetic test keys were generated with OpenSSL 4.1.0 using the public
RFC 5114 section 2.3 group (2048-bit p, 256-bit q). They contain no user secrets.
The encrypted container password is `public-test-password` and its intentionally
small iteration count is for interoperability tests only.

Generation commands (the public output is also used by the PKIX tests):

```sh
openssl genpkey -genparam -algorithm DHX -pkeyopt dh_rfc5114:3 -out params.pem
openssl genpkey -paramfile params.pem -out key.pem
openssl pkey -in key.pem -pubout -outform DER -out public.der
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out private.der
openssl pkcs8 -topk8 -in key.pem -outform DER -v2 aes-256-cbc -iter 2 \
  -passout pass:public-test-password -out encrypted.der
```
