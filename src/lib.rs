//! CUPS print jobs (macOS and Linux), for forensics: the control files
//! the scheduler keeps in its spool (`/var/spool/cups/c<job number>`, on
//! macOS `/private/var/spool/cups/`), one per job, kept after printing
//! (`PreserveJobHistory`): who printed what, from which application and
//! host, to which printer, and when.
//!
//! A control file is an IPP message (RFC 8010): a big-endian header (the
//! IPP version, the operation, the request id) then groups of attributes,
//! each group opened by a delimiter tag (1 operation, 2 job, 4 printer, 5
//! unsupported) and the whole closed by 3. An attribute is a value tag,
//! its name's size and name, its value's size and value; an attribute with
//! an empty name is another value of the one before. Values are integers
//! and enumerations (32-bit), booleans, dates (RFC 2579: year, month, day,
//! time to the tenth of a second, offset from UTC), and text: names and
//! texts in the charset the message declares, keywords, URIs and MIME
//! types in ASCII.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let job = cups::read(&std::fs::read("/var/spool/cups/c00001")?);
//! println!("{:?} printed {:?} to {:?} at {:?}", job.text("job-originating-user-name"),
//!     job.text("job-name"), job.text("printer-uri"), job.created());
//! # Ok(())
//! # }
//! ```
//!
//! Damage goes to `problems`, never a panic.

use common::time::{Precision, Ts};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The IPP versions CUPS writes.
const VERSIONS: [(u8, u8); 3] = [(1, 0), (1, 1), (2, 0)];
/// The tag ending the attributes.
const END_OF_ATTRIBUTES: u8 = 0x03;
/// The most attributes read, against damage.
const MAX_ATTRIBUTES: usize = 65_536;

/// Value tags.
mod tag {
    pub const NO_VALUE: u8 = 0x13;
    pub const INTEGER: u8 = 0x21;
    pub const BOOLEAN: u8 = 0x22;
    pub const ENUM: u8 = 0x23;
    pub const DATE_TIME: u8 = 0x31;
    pub const TEXT: u8 = 0x41;
    pub const NAME: u8 = 0x42;
    pub const KEYWORD: u8 = 0x44;
    pub const URI: u8 = 0x45;
    pub const URI_SCHEME: u8 = 0x46;
    pub const CHARSET: u8 = 0x47;
    pub const LANGUAGE: u8 = 0x48;
    pub const MIME_TYPE: u8 = 0x49;
}

/// A value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An integer or enumeration.
    Integer(i32),
    /// A boolean.
    Boolean(bool),
    /// A date and time (UTC; none when it doesn't read as one).
    DateTime(Option<Ts>),
    /// Text: a name, text, keyword, URI, charset, language or MIME type.
    Text(String),
    /// "No value".
    None,
    /// Bytes of another type, as stored.
    Other {
        /// Its value tag.
        tag: u8,
        /// Its bytes.
        bytes: Vec<u8>,
    },
}

/// An attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The group it is in (1 operation, 2 job, 4 printer, 5 unsupported).
    pub group: u8,
    /// Its name.
    pub name: String,
    /// Its values, in order.
    pub values: Vec<Value>,
}

/// A print job's control file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Job {
    /// The IPP version (`(2, 0)`).
    pub version: (u8, u8),
    /// The operation (5 a job's attributes, as CUPS writes control files).
    pub operation: u16,
    /// The request id.
    pub request_id: u32,
    /// Its attributes, in order.
    pub attributes: Vec<Attribute>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

impl Job {
    /// The first value of the attribute `name`.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.values.first())
    }

    /// The attribute's values as text, joined with `, `.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<String> {
        let texts: Vec<&str> = self
            .attributes
            .iter()
            .filter(|a| a.name == name)
            .flat_map(|a| &a.values)
            .filter_map(|v| match v {
                Value::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        (!texts.is_empty()).then(|| texts.join(", "))
    }

    /// The attribute's first value as an integer.
    #[must_use]
    pub fn integer(&self, name: &str) -> Option<i32> {
        match self.value(name)? {
            Value::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// When the job was created: `date-time-at-creation`, else
    /// `time-at-creation` (Unix seconds).
    #[must_use]
    pub fn created(&self) -> Option<Ts> {
        self.time("creation")
    }

    /// When it started printing (`…-at-processing`).
    #[must_use]
    pub fn processing(&self) -> Option<Ts> {
        self.time("processing")
    }

    /// When it ended (`…-at-completed`).
    #[must_use]
    pub fn completed(&self) -> Option<Ts> {
        self.time("completed")
    }

    fn time(&self, event: &str) -> Option<Ts> {
        let date = match self.value(&format!("date-time-at-{event}")) {
            Some(Value::DateTime(ts)) => *ts,
            _ => None,
        };
        date.or_else(|| {
            self.integer(&format!("time-at-{event}"))
                .filter(|&s| s > 0)
                .map(|s| Ts::from_unix_seconds(i64::from(s)))
        })
    }
}

/// Whether `head` starts like a control file: an IPP version CUPS writes,
/// then a delimiter tag after the header.
#[must_use]
pub fn is_control_file(head: &[u8]) -> bool {
    head.len() > 8
        && VERSIONS.contains(&(head[0], head[1]))
        && matches!(head[8], 0x01 | 0x02 | 0x04 | 0x05)
}

/// Read a control file.
#[must_use]
pub fn read(data: &[u8]) -> Job {
    let mut job = Job::default();
    let mut cursor = Cursor { data, at: 0 };
    let header = (|| {
        let version = (cursor.u8()?, cursor.u8()?);
        Some((version, cursor.u16()?, cursor.u32()?))
    })();
    let Some((version, operation, request_id)) = header else {
        job.problems.push("a header cut short".to_owned());
        return job;
    };
    if !VERSIONS.contains(&version) {
        job.problems.push(format!(
            "IPP version {}.{} not one CUPS writes",
            version.0, version.1
        ));
    }
    (job.version, job.operation, job.request_id) = (version, operation, request_id);
    let mut group = 0;
    let mut charset_is_utf8 = true;
    while job.attributes.len() < MAX_ATTRIBUTES {
        let Some(value_tag) = cursor.u8() else {
            job.problems
                .push("the attributes end without their end tag".to_owned());
            break;
        };
        if value_tag == END_OF_ATTRIBUTES {
            break;
        }
        if value_tag < 0x10 {
            group = value_tag;
            continue;
        }
        let at = cursor.at - 1;
        let Some((name, bytes)) = attribute(&mut cursor) else {
            job.problems
                .push(format!("offset {at:#x}: an attribute cut short"));
            break;
        };
        let value = value(value_tag, bytes, charset_is_utf8);
        if value_tag == tag::CHARSET {
            charset_is_utf8 = matches!(&value, Value::Text(t) if t.eq_ignore_ascii_case("utf-8"));
        }
        match job.attributes.last_mut() {
            Some(previous) if name.is_empty() => previous.values.push(value),
            _ => job.attributes.push(Attribute {
                group,
                name,
                values: vec![value],
            }),
        }
    }
    job
}

/// An attribute's name and value bytes, after its tag.
fn attribute<'a>(cursor: &mut Cursor<'a>) -> Option<(String, &'a [u8])> {
    let name_size = usize::from(cursor.u16()?);
    let name = String::from_utf8_lossy(cursor.take(name_size)?).into_owned();
    let value_size = usize::from(cursor.u16()?);
    Some((name, cursor.take(value_size)?))
}

/// A value from its tag and bytes.
fn value(value_tag: u8, bytes: &[u8], charset_is_utf8: bool) -> Value {
    let other = || Value::Other {
        tag: value_tag,
        bytes: bytes.to_vec(),
    };
    match value_tag {
        tag::NO_VALUE => Value::None,
        tag::INTEGER | tag::ENUM => bytes
            .try_into()
            .map_or_else(|_| other(), |b| Value::Integer(i32::from_be_bytes(b))),
        tag::BOOLEAN => match bytes {
            [0] => Value::Boolean(false),
            [1] => Value::Boolean(true),
            _ => other(),
        },
        tag::DATE_TIME => Value::DateTime(date_time(bytes)),
        tag::TEXT | tag::NAME if charset_is_utf8 => {
            Value::Text(String::from_utf8_lossy(bytes).into_owned())
        }
        tag::TEXT | tag::NAME => Value::Text(bytes.iter().map(|&b| char::from(b)).collect()),
        tag::KEYWORD
        | tag::URI
        | tag::URI_SCHEME
        | tag::CHARSET
        | tag::LANGUAGE
        | tag::MIME_TYPE => Value::Text(String::from_utf8_lossy(bytes).into_owned()),
        _ => other(),
    }
}

/// An RFC 2579 date: year (16 bits), month, day, hours, minutes, seconds,
/// tenths, then `+` or `-` and the hours and minutes from UTC; made UTC.
fn date_time(bytes: &[u8]) -> Option<Ts> {
    let [y0, y1, month, day, hours, minutes, seconds, tenths, direction, off_hours, off_minutes] =
        *bytes
    else {
        return None;
    };
    let year = i64::from(u16::from_be_bytes([y0, y1]));
    let valid = (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hours < 24
        && minutes < 60
        && seconds < 61
        && tenths < 10;
    if !valid {
        return None;
    }
    let days = common::time::days_from_civil(year, u32::from(month), u32::from(day));
    let local =
        days * 86_400 + i64::from(hours) * 3600 + i64::from(minutes) * 60 + i64::from(seconds);
    let offset = i64::from(off_hours) * 3600 + i64::from(off_minutes) * 60;
    let utc = match direction {
        b'+' => local - offset,
        b'-' => local + offset,
        _ => return None,
    };
    Some(Ts::from_ticks(
        utc.checked_mul(10_000_000)? + i64::from(tenths) * 1_000_000,
        Precision::Millisecond,
    ))
}

/// A big-endian reader over bytes.
struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Option<&'a [u8]> {
        let bytes = self.data.get(self.at..self.at.checked_add(size)?)?;
        self.at += size;
        Some(bytes)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_made_utc() {
        let date = [0x07, 0xdd, 11, 3, 19, 7, 21, 5, b'+', 1, 0];
        let ts = date_time(&date).unwrap();
        let utc = [0x07, 0xdd, 11, 3, 18, 7, 21, 5, b'+', 0, 0];
        assert_eq!(ts, date_time(&utc).unwrap());
        assert_eq!(date_time(&date[..5]), None);
    }

    #[test]
    fn other_files() {
        assert!(!is_control_file(b"not a control file"));
        assert!(!read(b"\x02").problems.is_empty());
    }
}
