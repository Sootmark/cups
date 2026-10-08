//! plaso's macOS control file (Apache-2.0, `tests/fixtures/plaso/`, see
//! its NOTICE): every event plaso's `cups_ipp` parser reads, read the same
//! (`tests/oracle/plaso.tsv`, written by `tests/oracle/gen.py`).

use common::time::Ts;
use proptest::prelude::*;

fn control_file() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/plaso/mac_cups_ipp"
    ))
    .unwrap()
}

#[test]
fn every_event_as_plaso_reads_it() {
    let data = control_file();
    assert!(cups::is_control_file(&data));
    let job = cups::read(&data);
    assert_eq!(job.problems, Vec::<String>::new());
    let text = |name: &str| job.text(name).unwrap_or_default();
    let values = [
        text("com.apple.print.JobInfo.PMApplicationName"),
        job.integer("copies").unwrap_or_default().to_string(),
        text("document-format"),
        text("job-originating-host-name"),
        text("job-uuid"),
        text("job-name"),
        text("com.apple.print.JobInfo.PMJobOwner"),
        text("DestinationPrinterID"),
        text("printer-uri"),
        text("job-originating-user-name"),
    ]
    .join("\t");
    let micros = |ts: Option<Ts>| ts.unwrap().ticks().unwrap() / 10;
    let mut got = vec![
        format!("Creation Time\t{}\t{values}", micros(job.created())),
        format!("Start Time\t{}\t{values}", micros(job.processing())),
        format!("End Time\t{}\t{values}", micros(job.completed())),
    ];
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/plaso.tsv").lines().collect();
    assert_eq!(got, expected);
    assert_eq!(job.text("job-sheets").as_deref(), Some("none, none"));
}

proptest! {
    #[test]
    fn damaged_control_files_read_without_panic(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..32),
        cut in any::<usize>(),
    ) {
        let mut data = control_file();
        for (at, byte) in flips {
            let at = at % data.len();
            data[at] = byte;
        }
        data.truncate(cut % (data.len() + 1));
        let _ = cups::read(&data);
    }
}
