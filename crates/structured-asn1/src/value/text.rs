//! Exact decimal materialization in the current execution domain.

use super::{Arc, DECIMAL_BLOCK, DECIMAL_BLOCK_DIGITS, Groups, Oid};
use crate::memory::{Memory, MemoryError, OwnedString};

pub(super) fn oid(value: Oid<'_>, execution: &Memory) -> Result<OwnedString, MemoryError> {
    let work = (value.as_bytes().len() as u64)
        .checked_mul(2)
        .ok_or(MemoryError::WorkExceeded)?;
    execution.charge_work(work)?;
    let mut text = execution.string();
    for (position, value) in value.arcs().enumerate() {
        if position > 0 {
            text.try_push('.')?;
        }
        append_arc(value, execution, &mut text)?;
    }
    Ok(text)
}

pub(super) fn arc(value: Arc<'_>, execution: &Memory) -> Result<OwnedString, MemoryError> {
    let mut text = execution.string();
    append_arc(value, execution, &mut text)?;
    Ok(text)
}

fn append_arc(
    value: Arc<'_>,
    execution: &Memory,
    text: &mut OwnedString,
) -> Result<(), MemoryError> {
    if let Some(value) = value.value {
        return append_integer(u128::from(value), 0, execution, text);
    }
    // Admit borrowing, leading-group inspection, and the accumulator pass
    // before examining the original encoding. X.690 8.19.2 does not impose
    // an arc width; resource refusal is distinct from malformed ASN.1.
    let work = (value.groups.len() as u64)
        .checked_mul(4)
        .ok_or(MemoryError::WorkExceeded)?;
    execution.charge_work(work)?;
    let adjusted = Groups::of(value.groups, value.offset);
    let significant = adjusted.significant();
    let first = adjusted.count() - significant;
    let mut narrow = Some(0u128);
    for group in adjusted.iter_from(first) {
        let Some(value) = narrow else { break };
        narrow = value
            .checked_mul(128)
            .and_then(|value| value.checked_add(u128::from(group)));
    }
    if let Some(value) = narrow {
        return append_integer(value, 0, execution, text);
    }

    let mut groups = execution.vector();
    groups.try_reserve_exact(significant)?;
    for group in adjusted.iter_from(first) {
        groups.try_push(group)?;
    }
    let mut blocks = execution.vector();
    let mut start = 0;
    while start < groups.len() {
        let work = ((groups.len() - start) as u64)
            .checked_mul(3)
            .ok_or(MemoryError::WorkExceeded)?;
        execution.charge_work(work)?;
        let mut carry = 0u128;
        for group in &mut groups[start..] {
            let current = carry * 128 + u128::from(*group);
            *group = u8::try_from(current / DECIMAL_BLOCK).expect("a base-128 quotient");
            carry = current % DECIMAL_BLOCK;
        }
        blocks.try_push(u64::try_from(carry).expect("a decimal-block remainder"))?;
        while start < groups.len() {
            execution.charge_work(1)?;
            if groups[start] != 0 {
                break;
            }
            start += 1;
        }
    }
    drop(groups);
    execution.charge_work(blocks.len() as u64)?;
    for (position, block) in blocks.into_iter().rev().enumerate() {
        let width = if position == 0 {
            0
        } else {
            DECIMAL_BLOCK_DIGITS
        };
        append_integer(u128::from(block), width, execution, text)?;
    }
    Ok(())
}

fn append_integer(
    mut value: u128,
    width: usize,
    execution: &Memory,
    text: &mut OwnedString,
) -> Result<(), MemoryError> {
    // u128 has at most 39 decimal digits; both conversion and safe UTF-8
    // validation use this fixed buffer and have no hidden heap allocation.
    execution.charge_work(78)?;
    debug_assert!(width <= 39);
    let mut buffer = [b'0'; 39];
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = b'0' + u8::try_from(value % 10).expect("a decimal digit");
        value /= 10;
        if value == 0 {
            break;
        }
    }
    start = start.min(buffer.len() - width);
    let digits = core::str::from_utf8(&buffer[start..]).expect("decimal ASCII");
    text.try_push_str(digits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryAccount;
    use alloc::sync::Arc as Shared;

    fn memory(bytes: usize, work: usize) -> Memory {
        Memory::new(Shared::new(MemoryAccount::new(bytes, work)))
    }

    #[test]
    fn exact_decimal_text_retains_storage_and_joint_offset() {
        // A packed first arc beyond u64 must subtract 80 before converting;
        // the owned text keeps its charge after the formatter returns.
        let value = Oid::from_bytes(&[0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x50]);
        let execution = memory(1024, 10_000);
        let text = oid(value, &execution).unwrap();
        assert_eq!(text.as_str(&execution).unwrap(), "2.18446744073709551616");
        assert_eq!(execution.used(), text.capacity());
        let last = arc(value.arcs().nth(1).unwrap(), &execution).unwrap();
        assert_eq!(last.as_str(&execution).unwrap(), "18446744073709551616");
        drop(last);
        drop(text);
        assert_eq!(execution.used(), 0);
    }

    #[test]
    fn wide_decimal_conversion_preserves_value_and_refuses_work() {
        // 2^133+1 exceeds the accumulator. Refusing a division pass must
        // release all scratch/output capacity and preserve the resource code.
        let mut bytes = alloc::vec![0x2a, 0x81];
        bytes.extend(core::iter::repeat_n(0x80, 18));
        bytes.push(1);
        let value = Oid::from_bytes(&bytes);
        let execution = memory(4096, 100_000);
        let text = oid(value, &execution).unwrap();
        assert_eq!(
            text.as_str(&execution).unwrap(),
            "1.2.10889035741470030830827987437816582766593"
        );
        assert_eq!(execution.used(), text.capacity());
        drop(text);
        assert_eq!(execution.used(), 0);
        let ceiling = memory(4096, 300);
        assert_eq!(oid(value, &ceiling).unwrap_err(), MemoryError::WorkExceeded);
        assert_eq!(ceiling.used(), 0);
    }
    #[test]
    fn exact_joint_offset_decimal_has_no_diagnostic_width_fallback() {
        // An independently calculated 2^4193-80 golden crosses the old
        // 512-group display cutoff. A permitted conversion must retain all
        // digits rather than substitute hex or a width description.
        let mut bytes = alloc::vec![0x81];
        bytes.extend(core::iter::repeat_n(0x80, 598));
        bytes.push(0);
        let value = Oid::from_bytes(&bytes);
        let execution = memory(10_000, 1_000_000);
        let text = oid(value, &execution).unwrap();
        let expected = concat!(
            "2.1654900240493839840417549342465538174997531941072712187042382756970654472212763888095965902169",
            "615267157244467175539104056311102204855537328823807613006042762516598303932544553705107935923484",
            "653672413598996308221126184400138957603329233183164341635242199533293473734019985640081827413617",
            "807991754688386007732448801816507833223853472115525918550008382772828266519998259896921883566507",
            "368393680693497258121588659870561916140012603529156830477102046629608277078324935534162327585060",
            "450056581221512009839469612987430297866354668417942813362508195233215279007874919786665168795197",
            "447675246728392422501927656080758048896053589354214178619329532361339021212963132352677448397446",
            "209694211194181892797494552580870752399335044351353635159673874512874070832209458757093813611298",
            "187418903470646052880381908068121452848649798416588478306833026823985718618062887395415841733846",
            "200829886005557791250816812792818149563792343631090922101449413053990734086407197645631097988823",
            "801776591575354687504968169093205038652606786635981895324573188970353246532712737019217172455366",
            "118973356436325519406083946173951662452188344827561064538236029829886752776933048107964115829166",
            "448059150679017462694454097605326672301015959652286844339634422560443429443239855151075674262591",
            "60397082150305712",
        );
        assert_eq!(text.as_str(&execution).unwrap(), expected);
        assert_eq!(execution.used(), text.capacity());
        drop(text);
        assert_eq!(execution.used(), 0);
    }
}
