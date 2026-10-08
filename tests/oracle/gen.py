"""Writes plaso.tsv: what plaso's cups_ipp parser reads from
tests/fixtures/plaso/mac_cups_ipp (psort JSON lines), one line per event:
which time, microseconds since 1970, then the job's values in a fixed
order (application, copies, document type, host, job id, job name, owner,
printer id, printer URI, user).

Run: python3 -I tests/oracle/gen.py plaso.jsonl > tests/oracle/plaso.tsv
"""

import json
import sys

KEYS = ["application", "copies", "document_type", "hostname", "job_identifier",
        "job_name", "owner", "printer_id", "uri", "username"]
lines = []
for line in open(sys.argv[1], encoding="utf-8"):
    e = json.loads(line)
    if e["data_type"] == "cups:ipp:event":
        lines.append("\t".join([e["timestamp_desc"], str(e["timestamp"])] + [str(e.get(k, "")) for k in KEYS]))
for line in sorted(lines):
    print(line)
