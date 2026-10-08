# cups

CUPS print jobs (macOS and Linux), for forensics: the control files the scheduler keeps in its spool (`/var/spool/cups/c<job>`), one per job: who printed what, from which application and host, to which printer, and when. Documents printed are evidence of what someone looked at and took away. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-cups = "0.1"
```

```rust
let job = cups::read(&std::fs::read("/var/spool/cups/c00001")?);
println!("{:?} printed {:?} to {:?} at {:?}", job.text("job-originating-user-name"),
    job.text("job-name"), job.text("printer-uri"), job.created());
```

## What you get

- `read(bytes)`: the IPP version, operation and request id, and every attribute in order with its group (operation, job, printer, unsupported) and values: integers and enumerations, booleans, dates (RFC 2579, made UTC), text (names and texts in the message's charset, keywords, URIs, MIME types), "no value", and other types as bytes. An attribute's additional values (an empty name) are added to it.
- `value(name)`, `text(name)` (all values joined with `, `), `integer(name)`, and the job's times: `created()`, `processing()`, `completed()` (`date-time-at-…`, else `time-at-…` in Unix seconds).
- The names that matter most: `job-originating-user-name`, `job-originating-host-name`, `job-name`, `document-format`, `printer-uri`, `job-uuid`, `copies`, and macOS's `com.apple.print.JobInfo.PMApplicationName` and `PMJobOwner` (the user's full name).
- `is_control_file(head)`: an IPP version CUPS writes, then a delimiter tag.
- Damage goes to `problems`, never a panic.

## How it's checked

- plaso's macOS control file (Apache-2.0, `tests/fixtures/plaso/`, see its NOTICE): every event plaso's `cups_ipp` parser reads, read the same (`tests/oracle/`).
- Property tests: damaged control files give attributes, problems or nothing, never a panic.

## Not yet

- The spooled documents themselves (`d<job>-<n>`).

## Licence

MIT or Apache-2.0, at your option.
