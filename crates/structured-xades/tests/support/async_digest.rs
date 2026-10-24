//! Suspending input must not outlive the original XML generation silently.

use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use structured_cms::stream::AsyncSource;

struct Input<'a> {
    xml: &'a Tree,
    change: bool,
    incomplete: bool,
}
impl AsyncSource for Input<'_> {
    type Error = SourceFailure;
    async fn stream<'q, W: Work + 'q, R: Receiver + 'q>(
        &'q mut self,
        receiver: &'q mut R,
        work: &'q W,
    ) -> Result<(), Self::Error> {
        let mut yielded = false;
        core::future::poll_fn(|context| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        work.charge_work(3).map_err(SourceFailure::Resource)?;
        receiver.write(b"abc").map_err(SourceFailure::Receiver)?;
        if self.change {
            self.xml.generation.set(self.xml.generation.get() + 1);
        }
        if self.incomplete {
            return Err(SourceFailure::Incomplete);
        }
        Ok(())
    }
}
fn finish<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the deterministic fixture only suspends once"),
    }
}

#[test]
fn asynchronous_digest_rechecks_xml_generation_before_finalization() {
    // A generation change during external acquisition invalidates the original
    // method/value association before finish, even when every byte hashes well.
    for baseline in [false, true] {
        let (xml, reference) = fixture();
        let work = funded();
        let provider = Oracle::new(Mode::Ready);
        let mut input = Input {
            xml: &xml,
            change: true,
            incomplete: false,
        };
        let error = if baseline {
            finish(digest::check_async(
                &xml, reference, &mut input, &provider, &work,
            ))
        } else {
            finish(digest::check_xml_async(
                &xml, reference, &mut input, &provider, &work,
            ))
        }
        .unwrap_err();
        assert!(matches!(error, binary::Error::Access {
            cause: AccessError::Changed { node }, ..
        } if node == reference.value));
        assert_eq!(provider.started.get(), 1);
        assert_eq!(provider.finished.get(), 0);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn asynchronous_source_failure_keeps_precedence_over_a_later_generation_check() {
    // A failed source has no valid input to finish. The original acquisition
    // cause must survive, even if that same source also invalidated the XML.
    let (xml, reference) = fixture();
    let work = funded();
    let provider = Oracle::new(Mode::Ready);
    let mut input = Input {
        xml: &xml,
        change: true,
        incomplete: true,
    };
    let error = finish(digest::check_async(
        &xml, reference, &mut input, &provider, &work,
    ))
    .unwrap_err();
    assert!(matches!(
        error,
        binary::Error::Callback {
            cause: digest::Error::Source(SourceFailure::Incomplete),
            ..
        }
    ));
    assert_eq!(provider.finished.get(), 0);
    assert_eq!(work.used(), 0);
}

#[test]
fn asynchronous_digest_finishes_the_same_original_declared_value_after_pending() {
    // Ordinary successful suspension keeps one moved declared-value buffer
    // and the real SHA256 result, with no second acquisition or retained copy.
    let (xml, reference) = fixture();
    let work = funded();
    let provider = Oracle::new(Mode::Ready);
    let mut input = Input {
        xml: &xml,
        change: false,
        incomplete: false,
    };
    assert_eq!(
        finish(digest::check_async(
            &xml, reference, &mut input, &provider, &work
        ))
        .unwrap(),
        Agreement::Matches
    );
    assert_eq!(provider.started.get(), 1);
    assert_eq!(provider.finished.get(), 1);
    assert_eq!(work.used(), 0);
}
