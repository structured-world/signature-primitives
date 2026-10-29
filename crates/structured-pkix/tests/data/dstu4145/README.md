# Public Ukrainian certificate framing samples

These are unmodified public certificates extracted from the CZO's public
[CA bundle](https://czo.gov.ua/download/certificates/CACertificates.p7b),
retrieved on 2026-10-29. The downloaded bundle's SHA-256 is
`efc6a4ecf5ca10dd099335fbf2c1173d597110b4eb431cb89652e7b7369029c4`.

The tests use them as independent ASN.1 framing evidence, not trusted anchors,
mathematical vectors, legal-compliance evidence or a cryptographic verdict.
Their Ukrainian names and signed payloads are intentional original test data.

- `kupyna-le.der`: Kupyna signature and the older GOST/DSTU key identifier.
- `gost-le.der`: little-endian GOST/DSTU identifier.
- `gost-be.der`: big-endian GOST/DSTU key identifier.

SHA-256:

```text
5f8a49d0fdc3b1e427552a8e968b39b7f23913b39009e3b0e2eefc06fad07eb9  kupyna-le.der
16d0488976bd43f39161308920e65cda4cac1aa196f75c07115176800db184f5  gost-le.der
85385da37290f5c53a22a2903643cf823dee294bd2ebb0d025fcd61a3b8e2eb3  gost-be.der
```
