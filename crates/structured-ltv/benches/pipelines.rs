//! Release-mode microbenchmarks for common validation operations.
//! Run with `cargo bench -p structured-ltv --bench pipelines`.

use sha2::{Digest as _, Sha256};
use std::{hint::black_box, sync::Arc, time::Instant as Clock};
use structured_asn1::{
    Encoding, Limits, Parser,
    digest::{Digest, Resolution},
    length::DerLength,
    memory::{Memory, MemoryAccount, MemoryError, Work},
};
use structured_cms::{
    digest::{DigestBatch, SingleDigest},
    provider::ProviderSession,
};
use structured_ltv::{
    pki::status::{ExpiryEvidence, Status},
    validation::{
        Anchor, Chain, Changes, Context, ETSI_TS_119_312_V2_1_1, Elements, Facts, Format, Order,
        Path, Recognition, Reference, Requirements, Signer, Time, Value, validate,
    },
};
use structured_pkix::{crl::CertificateList, temporal::Instant};

fn measure(label: &str, iterations: u32, mut operation: impl FnMut()) {
    const SAMPLES: usize = 61;
    for _ in 0..iterations {
        operation();
    }
    let mut samples = [0.0; SAMPLES];
    for sample in &mut samples {
        let start = Clock::now();
        for _ in 0..iterations {
            operation();
        }
        *sample = start.elapsed().as_secs_f64() * 1e9 / f64::from(iterations);
    }
    samples.sort_unstable_by(f64::total_cmp);
    println!(
        "{label}: p50 {:.2} ns/op, p95 {:.2} ns/op (batches of {iterations})",
        samples[SAMPLES / 2],
        samples[(SAMPLES - 1) * 95 / 100]
    );
}

fn lengths(memory: &Memory) {
    let mut value = vec![0x04, 0x82, 0x01, 0x00];
    value.resize(260, 0xa5);
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: u64::MAX,
            ..Limits::default()
        },
        memory.clone(),
    );
    measure("asn1/two-octet-length", 4096, || {
        let mut reader = parser.read(black_box(&value), 0).unwrap();
        black_box(reader.next_element().unwrap().unwrap().contents());
    });
}

fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    output.extend_from_slice(DerLength::new(bytes.len() as u64).as_bytes());
    output.extend_from_slice(bytes);
    output
}

fn crl_fixture(extra_extensions: u8) -> Vec<u8> {
    let algorithm = tlv(0x30, &tlv(0x06, &[42, 134, 72, 206, 61, 4, 3, 2]));
    let name = tlv(
        0x30,
        &tlv(0x31, &tlv(0x30, b"\x06\x03\x55\x04\x03\x0c\x01R")),
    );
    let mut extensions = Vec::new();
    for i in 0..extra_extensions {
        extensions.extend(tlv(0x30, &[6, 3, 42, 3, i, 4, 2, 5, 0]));
    }
    // A synthetic noncritical IDP exercises lookup through the complete
    // catalogue. This benchmark measures no authentication or signature math.
    extensions.extend(tlv(0x30, b"\x06\x03\x55\x1d\x1c\x04\x02\x30\x00"));
    let tbs = tlv(
        0x30,
        &[
            tlv(2, &[1]),
            algorithm.clone(),
            name,
            tlv(0x17, b"250104000000Z"),
            tlv(0xa0, &tlv(0x30, &extensions)),
        ]
        .concat(),
    );
    tlv(0x30, &[tbs, algorithm, tlv(3, &[0, 1])].concat())
}

fn crl_access(memory: &Memory) {
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: u64::MAX,
            ..Limits::default()
        },
        memory.clone(),
    );
    for extra in [0, 32] {
        let bytes = crl_fixture(extra);
        let list = CertificateList::read(&parser, &bytes, 0).unwrap();
        let label = format!("pkix/idp-lookup/{}", extra + 1);
        measure(&label, 4096, || {
            black_box(
                black_box(&list)
                    .noncritical_issuing_distribution_point(memory)
                    .unwrap(),
            );
        });
        let label = format!("pkix/crl-read/{}", extra + 1);
        measure(&label, 512, || {
            let parser = Parser::der(memory.clone());
            black_box(CertificateList::read(&parser, black_box(&bytes), 0).unwrap());
        });
    }
}

struct Hash;
impl Digest<'_> for Hash {
    type Identity = ();
    type State = Sha256;
    type Output = [u8; 32];
    type Error = MemoryError;

    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(
        &self,
        (): &(),
        (): &(),
        work: &W,
    ) -> Result<std::cmp::Ordering, MemoryError> {
        work.charge_work(1)?;
        Ok(std::cmp::Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), work: &W) -> Result<Resolution<Sha256>, MemoryError> {
        work.charge_work(1)?;
        Ok(Resolution::Supported(Sha256::new()))
    }
    fn update<W: Work>(
        &self,
        state: &mut Sha256,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), MemoryError> {
        work.charge_work(bytes.len() as u64)?;
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, work: &W) -> Result<Self::Output, MemoryError> {
        work.charge_work(64)?;
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &Self::Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, MemoryError> {
        work.charge_work(32)?;
        Ok(output == expected)
    }
}

fn digest_batches(memory: &Memory) {
    let provider = ProviderSession::new(Hash);
    for count in [1, 4] {
        let label = format!("cms/prepare/{count}");
        measure(&label, 4096, || {
            let mut identities = memory.vector();
            for _ in 0..count {
                identities.try_push(()).unwrap();
            }
            black_box(
                DigestBatch::prepare(&provider, black_box(identities), memory, "bench", 0).unwrap(),
            );
        });
    }
}

fn digest_single(memory: &Memory) {
    let provider = ProviderSession::new(Hash);
    let data = [0x5a; 4096];
    for length in [64, 4096] {
        let bytes = &data[..length];
        measure(&format!("cms/one/batch/{length}"), 4096, || {
            let mut identities = memory.vector();
            identities.try_push(()).unwrap();
            let memo = DigestBatch::prepare(&provider, identities, memory, "bench", 0)
                .unwrap()
                .run(&mut [black_box(bytes)], memory)
                .unwrap();
            black_box(memo.for_request(0, memory).unwrap().unwrap().as_bytes());
        });
        measure(&format!("cms/one/direct/{length}"), 4096, || {
            let output = SingleDigest::prepare(&provider, (), memory, "bench", 0)
                .unwrap()
                .run(&mut [black_box(bytes)], memory)
                .unwrap();
            black_box(output.as_bytes());
        });
    }
}

fn validate_paths(memory: &Memory) {
    let now = Instant::new(1000, 0).unwrap();
    let policy = Requirements {
        crypto: ETSI_TS_119_312_V2_1_1,
        elements: Elements::NONE,
        timestamp_delay: None,
    };
    let anchor = Anchor {
        current: Recognition::Recognized,
        over_interval: Recognition::Recognized,
    };
    let ordinary = Path {
        chain: Chain::Valid,
        anchor,
        authorities: &[],
        materials: &[],
        revocation_issuers: &[],
        revocation_retry: None,
    };
    let mut paths = [ordinary; 64];
    for scenario in [0, 1, 2] {
        let paths = match scenario {
            0 => &paths[..1],
            1 => &paths[..],
            _ => {
                paths[63].chain = Chain::DirectTrust;
                &paths[..]
            }
        };
        let facts = Facts {
            format: Format::Conformant,
            context: Context::Ready,
            signer: Some(Signer {
                not_before: Instant::new(500, 0).unwrap(),
                not_after: Instant::new(2000, 0).unwrap(),
                revocation: Status::NotRevoked {
                    basis: 0,
                    later: None,
                },
                expiry_evidence: ExpiryEvidence::Unestablished,
            }),
            references: &[Reference::Intact],
            value: Value::Verified,
            materials: &[],
            signed_attribute_materials: &[],
            elements: Elements::NONE,
            time: Time {
                after: None,
                before: None,
            },
            content_timestamp: None,
            paths,
            truncated: false,
            order: Order::Coherent,
            signature_timestamp: false,
            signature_timestamps: &[],
            claimed_signing_time: None,
            utc: None,
            changes: Changes::NotApplicable,
            now,
        };
        let label = ["ltv/one-path", "ltv/64-ordinary", "ltv/64-last-direct"][scenario];
        measure(label, 4096, || {
            black_box(validate(black_box(&facts), black_box(&policy), memory).unwrap());
        });
    }
}

fn main() {
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 24, usize::MAX)));
    lengths(&memory);
    crl_access(&memory);
    validate_paths(&memory);
    digest_batches(&memory);
    digest_single(&memory);
}
