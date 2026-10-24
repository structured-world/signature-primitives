//! One PDF byte-value grammar for resident and suspended original-range input.

use crate::bytes::{Form, is_space};

#[derive(Clone, Copy)]
enum State {
    Ready,
    NameHigh,
    NameLow(u8),
    Escape,
    SkipLf,
    Octal(u8, u8),
    HexLow(u8),
    End,
    Failed,
}

pub(crate) enum Step {
    /// Exactly one input byte was consumed, with no output.
    More,
    /// Output may precede consumption of the next byte (octal lookahead).
    Byte {
        value: u8,
        consumed: bool,
    },
    End,
    Malformed,
}

pub(crate) struct Decoder {
    form: Form,
    state: State,
}

impl Decoder {
    pub(crate) fn new(form: Form) -> Self {
        Self {
            form,
            state: State::Ready,
        }
    }

    pub(crate) fn step(&mut self, input: Option<u8>) -> Step {
        match self.state {
            State::End => return Step::End,
            State::Failed => return Step::Malformed,
            State::NameHigh => {
                let Some(value) = input.and_then(hex) else {
                    return self.fail();
                };
                self.state = State::NameLow(value);
                return Step::More;
            }
            State::NameLow(high) => {
                let Some(low) = input.and_then(hex) else {
                    return self.fail();
                };
                let value = high * 16 + low;
                if value == 0 {
                    return self.fail();
                }
                self.state = State::Ready;
                return Step::Byte {
                    value,
                    consumed: true,
                };
            }
            State::Escape => return self.escaped(input),
            State::SkipLf => {
                self.state = State::Ready;
                if input == Some(b'\n') {
                    return Step::More;
                }
                // A non-LF byte belongs to the next value. Process it here
                // without a second source read, work charge or async request.
            }
            State::Octal(value, count) => {
                if let Some(byte @ b'0'..=b'7') = input {
                    // ISO32000-1§7.3.4.2 explicitly ignores high-order overflow.
                    let value = value.wrapping_mul(8).wrapping_add(byte - b'0');
                    if count == 2 {
                        self.state = State::Ready;
                        return Step::Byte {
                            value,
                            consumed: true,
                        };
                    }
                    self.state = State::Octal(value, count + 1);
                    return Step::More;
                }
                self.state = State::Ready;
                return Step::Byte {
                    value,
                    consumed: false,
                };
            }
            State::HexLow(high) => {
                if let Some(byte) = input {
                    if is_space(byte) {
                        return Step::More;
                    }
                    let Some(low) = hex(byte) else {
                        return self.fail();
                    };
                    self.state = State::Ready;
                    return Step::Byte {
                        value: high * 16 + low,
                        consumed: true,
                    };
                }
                // ISO32000-1§7.3.4.3 pads an odd final nibble with zero.
                self.state = State::End;
                return Step::Byte {
                    value: high * 16,
                    consumed: false,
                };
            }
            State::Ready => {}
        }
        self.ready(input)
    }

    fn ready(&mut self, input: Option<u8>) -> Step {
        let Some(byte) = input else {
            self.state = State::End;
            return Step::End;
        };
        match self.form {
            Form::Name => {
                // ISO32000-1§7.3.5: # introduces exactly two hexadecimal
                // digits; a name cannot contain an escaped or literal zero.
                // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
                if byte == 0 {
                    return self.fail();
                }
                if byte == b'#' {
                    self.state = State::NameHigh;
                    return Step::More;
                }
                Step::Byte {
                    value: byte,
                    consumed: true,
                }
            }
            Form::Literal => match byte {
                b'\\' => {
                    self.state = State::Escape;
                    Step::More
                }
                b'\r' => {
                    self.state = State::SkipLf;
                    Step::Byte {
                        value: b'\n',
                        consumed: true,
                    }
                }
                _ => Step::Byte {
                    value: byte,
                    consumed: true,
                },
            },
            Form::Hexadecimal => {
                if is_space(byte) {
                    return Step::More;
                }
                let Some(high) = hex(byte) else {
                    return self.fail();
                };
                self.state = State::HexLow(high);
                Step::More
            }
        }
    }

    fn escaped(&mut self, input: Option<u8>) -> Step {
        let Some(byte) = input else {
            return self.fail();
        };
        self.state = State::Ready;
        let value = match byte {
            b'\n' => return Step::More,
            b'\r' => {
                self.state = State::SkipLf;
                return Step::More;
            }
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'b' => 8,
            b'f' => 12,
            b'0'..=b'7' => {
                self.state = State::Octal(byte - b'0', 1);
                return Step::More;
            }
            // §7.3.4.2: unlisted escapes ignore only the backslash.
            other => other,
        };
        Step::Byte {
            value,
            consumed: true,
        }
    }

    fn fail(&mut self) -> Step {
        self.state = State::Failed;
        Step::Malformed
    }
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
