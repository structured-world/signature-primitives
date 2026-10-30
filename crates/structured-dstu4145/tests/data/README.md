# Public mathematical verification samples

The two PEM files contain unmodified NBU CA certificates from the public
[CZO bundle](https://czo.gov.ua/download/certificates/CACertificates.p7b),
retrieved on 2026-10-30. The bundle SHA-256 is
`efc6a4ecf5ca10dd099335fbf2c1173d597110b4eb431cb89652e7b7369029c4`.

The zero-based bundle ordinals are 760 and 761. PEM is an outer text encoding;
the signed certificate DER is unchanged. Ukrainian names and signed values
are intentional original test data. The tests check the actual self-signature
mathematics, without treating either certificate as a trusted anchor or
asserting legal compliance.

SHA-256 of the decoded DER:

```text
f66beb7240ec89fe38cf425d09bc9a898d430288c7a6bebf7b893c0053f127c9  nbu-gost.pem
eabda5ea5f53f018a87d0e915489d63e3fb47a7e0c0ede7023af16ea01540473  nbu-kupyna.pem
```
