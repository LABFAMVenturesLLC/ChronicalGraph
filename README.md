# ChronicalGraph
Converts Log2Timeline into an Evidence Graph

Instead of presenting millions of chronological rows, it answers questions such as:
- How did this executable arrive on the system?
- Which user launched it?
- What happened immediately before and after execution?
- Which domains, IPs, files, accounts, and removable devices are connected?
- Does the evidence support or contradict a particular incident hypothesis?
- Which conclusions rely on weak or ambiguous timestamps?

Evidence graph
Represent forensic objects as nodes:
- Files and hashes
- Processes and executables
- Users and accounts
- Hosts and devices
- Domains, URLs, and IP addresses
- Browser downloads and searches
- USB devices
- Registry keys
- Logon sessions
- Emails or cloud objects
- Plaso events

The system produces:
- Supporting evidence
- Contradicting evidence
- Missing evidence
- Confidence score
- Alternative explanations
- Exact event provenance

This is more useful—and safer—than simply asking an AI model to “summarize the timeline.”
