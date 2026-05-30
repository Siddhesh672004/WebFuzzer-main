# Third-Party Notices

SmartFuzz is built as an original Node.js scanning engine. It does **not** bundle,
link against, or execute any third-party scanner at runtime. Where we benefit from
external open-source projects, we do so in one of two clearly-bounded ways:

1. **Data only** — we ingest publicly published *payload wordlists* and *path lists*
   as plain text, seed them into our own database, and use them as input data.
2. **Clean-room port** — we read a project's published *detection patterns/heuristics*
   and re-implement equivalent logic from scratch in JavaScript. We copy no source code.

This document records every source, its license, and exactly how we use it, in the
spirit of full attribution.

---

## 1. SecLists
- **Project:** https://github.com/danielmiessler/SecLists
- **License:** MIT
- **How SmartFuzz uses it:** We ingest selected fuzzing wordlists
  (`Fuzzing/SQLi/*`, `Fuzzing/XSS/*`, `Fuzzing/LFI/*`, `Fuzzing/RCE/*`, etc.) as
  **data**, seeded into the `payloads` collection. No SecLists code is used.
- **Obligation:** Retain the MIT copyright notice (reproduced below).

## 2. PayloadsAllTheThings
- **Project:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **License:** MIT
- **How SmartFuzz uses it:** WAF-bypass / filter-evasion payload variants ingested as
  **data** for the mutation engine. No code is used.
- **Obligation:** Retain the MIT copyright notice.

## 3. FuzzDB
- **Project:** https://github.com/fuzzdb-project/fuzzdb
- **License:** Mixed — BSD-style, CC-BY-3.0, Apache-2.0, MIT across different files.
- **How SmartFuzz uses it:** Attack patterns organized by input type ingested as
  **data** for parameter-type-aware payload selection. No code is used.
- **Obligation:** Redistribute **with attribution**; preserve original notices.

## 4. OWASP ZAP — passive scan rules (`pscanrules`)
- **Project:** https://github.com/zaproxy/zap-extensions
- **License:** Apache License 2.0
- **How SmartFuzz uses it:** We studied the published regex patterns and detection
  heuristics and **re-implemented equivalent rules from scratch in JavaScript**
  (clean-room). No ZAP source code is copied or linked.
- **Obligation:** Apache-2.0 attribution (this NOTICE entry); no copied source to license.

## 5. Wapiti
- **Project:** https://github.com/wapiti-scanner/wapiti
- **License:** GNU GPL v2
- **How SmartFuzz uses it:** **Study-only architectural reference.** We read its
  crawler/analyzer design for ideas and implemented our own Node.js version from
  scratch. We do **not** copy, link, import, or execute Wapiti. Because no GPL code
  enters our codebase, the GPL does not extend to SmartFuzz.
- **Obligation:** Cited here as a reference, not a dependency.

## 6. Nikto — `db_tests`
- **Project:** https://github.com/sullo/nikto
- **License:** GNU GPL v2
- **How SmartFuzz uses it:** The exposed-paths checks in our Exposed Files Scanner are
  informed by the categories of well-known sensitive paths Nikto documents. Our path
  list is maintained as our own **data** file (`worker/src/knowledge/sensitivePaths.json`);
  we do not ship Nikto's database file or any Nikto code.
- **Obligation:** Cited here as a reference.

---

## License notice reproductions

### MIT (SecLists, PayloadsAllTheThings, and MIT-licensed FuzzDB files)
```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. ...
```

### Apache License 2.0 (OWASP ZAP)
Full text: https://www.apache.org/licenses/LICENSE-2.0
> Portions of SmartFuzz's response-analysis heuristics are clean-room
> re-implementations inspired by OWASP ZAP's passive scan rules
> (Apache-2.0). No original ZAP source is included.

### CC-BY-3.0 (portions of FuzzDB)
Full text: https://creativecommons.org/licenses/by/3.0/
> Attribution: FuzzDB project (https://github.com/fuzzdb-project/fuzzdb).

---

*If you are a maintainer of any project listed here and believe the attribution
above is incomplete or inaccurate, please open an issue — we will correct it
promptly.*
