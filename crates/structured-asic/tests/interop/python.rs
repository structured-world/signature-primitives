//! Python/zlib are independent test oracles, never a production runtime path.

use super::support::{Descriptor, File, Input, finish, memory, zip};
use std::{
    io::Write,
    process::{Command, Stdio},
};
use structured_asic::{Limits, Session, zip::Archive};

fn python(script: &str, input: &[u8]) -> Vec<u8> {
    let mut child = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("interop-tests requires Python3 with its standard zipfile/zlib modules");
    // Inputs here are bounded trusted fixtures. Writing concurrently avoids
    // pipe backpressure when the independent oracle emits a large result.
    let mut stdin = child.stdin.take().unwrap();
    let output = std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            stdin.write_all(input).unwrap();
        });
        let result = child.wait_with_output().unwrap();
        writer.join().unwrap();
        result
    });
    assert!(
        output.status.success(),
        "Python ZIP oracle: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn python_zipfile_independently_reads_literal_zip64_deflate_and_descriptor_frames() {
    // Cross-check each original occurrence by ZipInfo, never by a duplicate-
    // collapsing filename lookup. No member is extracted to the filesystem.
    let large = b"independent raw DEFLATE blocks".repeat(3000);
    for zip64 in [false, true] {
        for descriptor in [Descriptor::None, Descriptor::Unsigned, Descriptor::Signed] {
            let mut file = File::stored(b"document.bin", &large);
            file.zip64 = zip64;
            file.deflate = true;
            file.descriptor = descriptor;
            let built = zip(&[file, File::stored(b"empty", b"")]);
            let output = python(
                r"
import io, sys, zipfile
with zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())) as archive:
    for entry in archive.infolist():
        data = archive.read(entry)
        sys.stdout.buffer.write(len(data).to_bytes(8, 'little'))
        sys.stdout.buffer.write(data)
",
                &built.bytes,
            );
            let mut expected = Vec::new();
            expected.extend_from_slice(&(large.len() as u64).to_le_bytes());
            expected.extend_from_slice(&large);
            expected.extend_from_slice(&0_u64.to_le_bytes());
            assert_eq!(output, expected);
        }
    }
}

#[test]
fn common_reader_accepts_independent_streamed_zip64_with_dynamic_huffman_blocks() {
    // Python's unseekable sink emits real signed descriptors. force_zip64
    // produces local ZIP64 even though small central sizes fit classic fields.
    let payload = b"dynamic Huffman repetition and original UTF-8 bytes\n".repeat(3000);
    let bytes = python(
        r"
import io, sys, zipfile
class Forward(io.BytesIO):
    def seek(self, *args):
        raise OSError('nonseekable fixture')
output = Forward()
data = sys.stdin.buffer.read()
with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    with archive.open('document.bin', 'w', force_zip64=True) as entry:
        for at in range(0, len(data), 71):
            entry.write(data[at:at+71])
    archive.writestr('empty', b'')
sys.stdout.buffer.write(output.getvalue())
",
        &payload,
    );
    let input = Input::new(bytes, 11);
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    assert_eq!(archive.len(), 2);
    assert!(archive.faults(&work).unwrap().next().is_none());
    let member = archive.member(0, &work).unwrap().unwrap();
    assert_eq!(finish(member.read_bytes(&work)).unwrap().as_ref(), payload);
    assert!(
        finish(archive.member(1, &work).unwrap().unwrap().read_bytes(&work))
            .unwrap()
            .is_empty()
    );
    drop(archive);
    assert_eq!(work.used(), 0);
}
