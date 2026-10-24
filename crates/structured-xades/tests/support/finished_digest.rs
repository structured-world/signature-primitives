use super::*;
use structured_cms::digest::DigestBatch;

struct Provider {
    oracle: Oracle,
    compared: Cell<usize>,
    matched: Cell<usize>,
    refuse_compare: bool,
}
impl Provider {
    fn new() -> Self {
        Self {
            oracle: Oracle::new(Mode::Ready),
            compared: Cell::new(0),
            matched: Cell::new(0),
            refuse_compare: false,
        }
    }
}
impl<'a> Digest<'a> for Provider {
    // The second test-only function reverses SHA256's output. These are truly
    // different functions/identities, despite equal output widths.
    type Identity = bool;
    type State = (<Oracle as Digest<'a>>::State, bool);
    type Output = Output;
    type Error = Failure;
    fn width(&self, _: &bool) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, a: &bool, b: &bool, work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1).map_err(Failure::Resource)?;
        self.compared.set(self.compared.get() + 1);
        if self.refuse_compare {
            return Err(Failure::Refused);
        }
        Ok(a.cmp(b))
    }
    fn start<W: Work>(
        &'a self,
        reversed: &bool,
        work: &W,
    ) -> Result<Resolution<Self::State>, Failure> {
        self.oracle.start(&(), work).map(|r| match r {
            Resolution::Supported(state) => Resolution::Supported((state, *reversed)),
            Resolution::Unsupported => Resolution::Unsupported,
            Resolution::Malformed => Resolution::Malformed,
        })
    }
    fn update<W: Work>(
        &self,
        state: &mut Self::State,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Failure> {
        self.oracle.update(&mut state.0, bytes, work)
    }
    fn finish<W: Work>(&self, state: Self::State, work: &W) -> Result<Output, Failure> {
        let mut output = self.oracle.finish(state.0, work)?;
        if state.1 {
            work.charge_work(32).map_err(Failure::Resource)?;
            match &mut output {
                Output::Full(bytes) => bytes.reverse(),
                Output::Short(bytes) => bytes.reverse(),
            }
        }
        Ok(output)
    }
    fn matches<W: Work>(
        &self,
        _: &bool,
        output: &Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        self.matched.set(self.matched.get() + 1);
        self.oracle.matches(&(), output, expected, work)
    }
}
impl DigestProvider<'_, Tree> for Provider {
    fn classify(&self, _: &bool) -> structured_xades::hashes::HashClass {
        structured_xades::hashes::HashClass::OtherKnown
    }
    fn resolve<W: Work>(
        &self,
        access: &Access<'_, Tree, W>,
        node: usize,
    ) -> Result<Resolution<bool>, Failure> {
        self.oracle.resolve(access, node).map(|r| match r {
            Resolution::Supported(()) => Resolution::Supported(false),
            Resolution::Unsupported => Resolution::Unsupported,
            Resolution::Malformed => Resolution::Malformed,
        })
    }
}

#[test]
fn actual_finished_digest_comparison_never_restarts_or_replays_the_source() {
    // A common batch, not arbitrary bytes, creates the compared receipt.
    // XML method/value checking then reuses the same selected native provider.
    for matches in [false, true] {
        let (mut xml, reference) = fixture();
        if !matches {
            xml.binary[0] ^= 1;
        }
        let work = funded();
        let provider = Provider::new();
        let mut ids = work.vector();
        ids.try_push(false).unwrap();
        let batch = DigestBatch::prepare(&provider, ids.into_owned(), &work, "input", 0).unwrap();
        let mut source = Tracked::new();
        let memo = batch.run(&mut source, &work).unwrap();
        let output = memo.for_request(0, &work).unwrap().unwrap();
        assert!(core::ptr::eq(
            output.finished().provider(),
            core::ptr::from_ref(&provider)
        ));
        let before = (
            provider.oracle.started.get(),
            provider.oracle.updated.get(),
            provider.oracle.finished.get(),
        );
        assert_eq!(
            digest::check_xml_finished(&xml, reference, output.finished(), &work).unwrap(),
            if matches {
                Agreement::Matches
            } else {
                Agreement::Differs
            }
        );
        assert_eq!(source.calls, 1);
        assert_eq!(
            (
                provider.oracle.started.get(),
                provider.oracle.updated.get(),
                provider.oracle.finished.get()
            ),
            before
        );
        assert_eq!(provider.oracle.resolved.get(), 1);
        assert_eq!(provider.matched.get(), 1);
        drop(memo);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn same_width_and_matching_declared_bytes_do_not_replace_full_algorithm_identity() {
    // The declared value equals the OTHER function's real result. Comparing
    // bytes first would falsely accept it as the XML-selected SHA256 result.
    let (mut xml, reference) = fixture();
    xml.binary.reverse();
    let work = funded();
    let provider = Provider::new();
    let mut ids = work.vector();
    ids.try_push(true).unwrap();
    let memo = DigestBatch::prepare(&provider, ids.into_owned(), &work, "input", 0)
        .unwrap()
        .run(&mut Tracked::new(), &work)
        .unwrap();
    let output = memo.for_request(0, &work).unwrap().unwrap();
    assert_eq!(output.as_bytes(), xml.binary);
    assert_eq!(
        digest::check_xml_finished(&xml, reference, output.finished(), &work).unwrap(),
        Agreement::Differs
    );
    assert_eq!(provider.matched.get(), 0);
    assert_eq!(provider.oracle.started.get(), 1);
}

#[test]
fn malformed_width_original_query_refusal_and_provider_cause_remain_distinct() {
    // A completed digest cannot bypass width checks, pay for another query or
    // convert a refused semantic comparison into a negative document answer.
    let (mut xml, reference) = fixture();
    let work = funded();
    let mut provider = Provider::new();
    provider.refuse_compare = true;
    let mut ids = work.vector();
    ids.try_push(false).unwrap();
    let memo = DigestBatch::prepare(&provider, ids.into_owned(), &work, "input", 0)
        .unwrap()
        .run(&mut Tracked::new(), &work)
        .unwrap();
    let output = memo.for_request(0, &work).unwrap().unwrap();
    let error = digest::check_xml_finished(&xml, reference, output.finished(), &work).unwrap_err();
    assert!(matches!(
        error,
        binary::Error::Callback {
            cause: digest::Error::Provider(Failure::Refused),
            ..
        }
    ));
    assert_eq!(provider.matched.get(), 0);
    xml.binary.pop();
    assert_eq!(
        digest::check_xml_finished(&xml, reference, output.finished(), &work).unwrap(),
        Agreement::MalformedValue
    );
    let zero = structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 0),
    ));
    assert!(matches!(
        digest::check_xml_finished(&xml, reference, output.finished(), &zero),
        Err(binary::Error::Access {
            cause: AccessError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            },
            ..
        })
    ));
    assert_eq!(provider.oracle.finished.get(), 1);
}
