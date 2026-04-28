---
name: New attack pattern
about: Submit a new attack pattern for inclusion in the filters
title: '[PATTERN] '
labels: enhancement
assignees: ''
---

**Attack type**
[e.g. JSON config harvesting, webshell dropper, wp-login brute force]

**Apache log line (anonymize your IP)**
```
1.2.3.4 - - [28/Apr/2026:10:00:00 +0000] "GET /suspicious-path HTTP/1.1" 200 ...
```

**Suggested filter regex**
```
^<HOST> -.*"GET /suspicious-path HTTP
```

**Which jail should this go in?**
[e.g. apache-config-scan, apache-webshell, new jail needed]

**Attack volume observed**
[e.g. 500 requests over 2 hours]
