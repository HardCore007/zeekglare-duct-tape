# Third-Party Notices

ZeekGlare incorporates content from the following third-party projects. Each
retains its original license; notices are reproduced below as required.

---

## shuvonsec/claude-bug-bounty

**Repository:** https://github.com/shuvonsec/claude-bug-bounty
**Author:** shuvonsec (https://shuvonsec.me)
**License:** MIT

**What we use:** Vulnerability-class hunting heuristics and payload libraries
from `skills/web2-vuln-classes/SKILL.md`, specifically the SSRF IP-bypass
techniques and auth-bypass patterns. These feed `services/skills/_payloads.py`
and the `guidance` strings on individual `Skill` classes in
`services/skills/`.

**MIT License**

```
MIT License

Copyright (c) shuvonsec
```

(See full MIT text below — same template applies to all MIT-licensed sources.)

---

## SnailSploit/Claude-Red

**Repository:** https://github.com/SnailSploit/Claude-Red
**License:** MIT

**What we use:** Payload-library inspiration and bug-class hunting heuristics
from the offensive SKILL.md files (38 skills covering SQLi, XSS, SSRF, SSTI,
XXE, IDOR, RCE, deserialization, race conditions, smuggling, open redirect,
parameter pollution, GraphQL, JWT, OAuth). Specifically informed:

  - `services/skills/_payloads.py` — XSS_REFLECTED_VECTORS, OPEN_REDIRECT_PAYLOADS,
    CORS_TEST_ORIGINS, JWT_WEAK_SECRETS, TAKEOVER_EXTRA_FINGERPRINTS
  - `guidance` strings on `services/skills/{ssrf,xss_reflected,open_redirect,cors,jwt,subdomain_takeover}.py`

The MIT license text below covers this repo as well.

---

**MIT License (full text)**

```
MIT License

Copyright (c) shuvonsec
Copyright (c) SnailSploit

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
