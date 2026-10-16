//! Deterministic current-budget pressure at an original source-query boundary.

use super::{Cause, Cell, Memory, Name, Node, Snapshot, Tree, Work, Xml};

pub(super) struct Boundary<'a> {
    source: &'a Tree,
    calls: Cell<usize>,
    refusal: Option<(usize, &'a Memory, usize)>,
    held: Cell<Option<usize>>,
    inspection_refusal: Option<(usize, &'a Memory, usize)>,
}

impl<'a> Boundary<'a> {
    pub(super) fn observe(source: &'a Tree) -> Self {
        Self {
            source,
            calls: Cell::new(0),
            refusal: None,
            held: Cell::new(None),
            inspection_refusal: None,
        }
    }
    pub(super) fn exhaust(source: &'a Tree, at: usize, work: &'a Memory, leave: usize) -> Self {
        Self {
            source,
            calls: Cell::new(0),
            refusal: Some((at, work, leave)),
            held: Cell::new(None),
            inspection_refusal: None,
        }
    }
    pub(super) fn after_inspection(
        source: &'a Tree,
        node: usize,
        work: &'a Memory,
        leave: usize,
    ) -> Self {
        Self {
            inspection_refusal: Some((node, work, leave)),
            ..Self::observe(source)
        }
    }
    pub(super) fn calls(&self) -> usize {
        self.calls.get()
    }
    pub(super) fn held(&self) -> Option<usize> {
        self.held.get()
    }
}

impl Xml for Boundary<'_> {
    type Id = usize;
    type Document = u8;
    type Generation = u8;
    type Error = Cause;

    fn snapshot(&self) -> Snapshot<u8, u8> {
        let next = self.calls.get() + 1;
        self.calls.set(next);
        if let Some((at, work, leave)) = self.refusal
            && next == at
        {
            // Deliberate TEST injection, not XML parsing or product accounting.
            // Source-query order is stable; randomized map collision work is
            // deliberately NOT used to calibrate the late-refusal boundary.
            self.held.set(Some(work.used()));
            let remaining = work.work_remaining();
            assert!(remaining >= leave);
            work.charge_work(u64::try_from(remaining - leave).unwrap())
                .unwrap();
        }
        self.source.snapshot()
    }

    fn inspect<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        execution: &W,
        visitor: impl for<'view> FnOnce(Node<'view>) -> R,
    ) -> Result<R, Cause> {
        let result = self.source.inspect(snapshot, node, execution, visitor);
        if let Some((at, work, leave)) = self.inspection_refusal
            && node == at
            && self.held.get().is_none()
        {
            self.held.set(Some(work.used()));
            work.charge_work(u64::try_from(work.work_remaining() - leave).unwrap())
                .unwrap();
        }
        result
    }
    fn attribute<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        name: Name<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(Option<&'view str>) -> R,
    ) -> Result<R, Cause> {
        self.source
            .attribute(snapshot, node, name, execution, visitor)
    }
    fn first_child<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        parent: usize,
        execution: &W,
    ) -> Result<Option<usize>, Cause> {
        self.source.first_child(snapshot, parent, execution)
    }
    fn next_sibling<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        parent: usize,
        node: usize,
        execution: &W,
    ) -> Result<Option<usize>, Cause> {
        self.source.next_sibling(snapshot, parent, node, execution)
    }
}

impl super::SignatureXml for Boundary<'_> {
    fn signature_status<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        work: &W,
    ) -> Result<super::Status, Cause> {
        self.source.signature_status(snapshot, signature, work)
    }
    fn reference_count<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        work: &W,
    ) -> Result<usize, Cause> {
        self.source.reference_count(snapshot, signature, work)
    }
    fn reference<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        ordinal: usize,
        work: &W,
        visitor: impl for<'view> FnOnce(super::Reference<'view, usize>) -> R,
    ) -> Result<R, Cause> {
        self.source
            .reference(snapshot, signature, ordinal, work, visitor)
    }
    fn qualifying_target<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        qualifying: usize,
        work: &W,
    ) -> Result<super::Target<usize>, Cause> {
        self.source.qualifying_target(snapshot, qualifying, work)
    }
}
