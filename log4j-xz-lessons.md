# Lessons from Famous Dependency Failures: Log4Shell & xz-utils Backdoor

Sourced brief for the engineering sync. All facts below are taken from the cited open-web sources and the GitHub Advisory Database (GHSA records pulled live).

## Executive Summary

- **Log4Shell (CVE-2021-44228, GHSA-jfh8-c2jp-5v3q)**: Critical, CVSS 3.1 score 10.0 (vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H). Affected package `org.apache.logging.log4j:log4j-core` (Maven), vulnerable versions >= 2.0-beta9, < 2.15.0 (backport branches: >= 2.4.0 < 2.12.2 patched by 2.12.2; < 2.3.1 patched by 2.3.1; 2.12.3 also listed). **First fixed version: 2.15.0** (with backports 2.12.2, 2.3.1 and 2.12.3). Discovered by Chen Zhaojun of the Alibaba Cloud Security Team, privately disclosed to Apache on 24 Nov 2021, CVE published 10 Dec 2021. The name "Log4Shell" was coined by Free Wortley of LunaSec. Patching only 2.15.0 was NOT enough: three more CVEs followed in Dec 2021-Jan 2022 (CVE-2021-45046 critical 9.0 -> 2.16.0; CVE-2021-45105 high 8.6 -> 2.17.0/2.12.3; CVE-2021-44832 medium 6.6 -> 2.17.1/2.12.4/2.3.2). Classic case of a single vuln with an incomplete first fix requiring a second release.
- **xz-utils backdoor (CVE-2024-3094, GHSA-rxwq-x6h5-x525)**: Critical, CVSS 3.1 score 10.0 (vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H), CWE-506 Embedded Malicious Code. Classified in the GitHub Advisory Database as **Unreviewed** (not in the Malware section; the malware-type filter returns empty). No package or version range is listed — it is a tarball-level backdoor affecting 5.6.0 and 5.6.1, fixed in 5.6.2 (CISA recommends downgrade to 5.4.6 Stable). Discovered by Andres Freund, reported to the Openwall oss-security mailing list on 29 Mar 2024 08:51:26 -0700. The backdoor injected obfuscated build-to-host.m4 into upstream tarballs that extracts a prebuilt object file from test archives and modifies liblzma build behaviour; it targets x86-64 glibc systems and can hook OpenSSH's RSA_public_decrypt via the crc64_resolve IFUNC, enabling authentication bypass on sshd. Case of a vulnerability that is effectively malicious code rather than a classic bug.

## 1. Log4Shell — CVE-2021-44228 (December 2021)

### Who discovered it and how it was reported
- Chen Zhaojun of the Alibaba Cloud Security Team privately disclosed the vulnerability to the Apache Software Foundation on 24 November 2021. The CVE identifier was made available on 10 December 2021, before public disclosure; the moniker "Log4Shell" was given by Free Wortley of the LunaSec team.
- The vulnerability had existed unnoticed since at least 2013 and was disclosed privately; public awareness exploded after proof-of-concept exploits leaked (observed 9 Dec 2021), with >1.2 million attacks recorded within days.

### What made it serious
- Unauthenticated remote code execution: Log4j 2 performs string substitution on ${prefix:name} expressions; ${jndi:ldap://...} caused Log4j to load and execute arbitrary Java objects from attacker-controlled LDAP/RMI/etc. endpoints when message lookups were enabled.
- Default configuration impact: even plainly configured apps logging user input were vulnerable; the 2.15.0 fix did not disable attacker-controlled JNDI lookups in all situations (CVE-2021-45046), requiring 2.16.0 which disables JNDI by default and removes message-lookup support.
- Exploited as a zero-day; estimated to affect hundreds of millions of devices; Wiz/EY counted it in 93% of enterprise cloud environments. Apache rated it CVSS 10, the highest score.

### GitHub Advisory Database record (GHSA-jfh8-c2jp-5v3q)
- GHSA ID: GHSA-jfh8-c2jp-5v3q
- CVE: CVE-2021-44228
- Severity: Critical
- CVSS 3.1: 10.0 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H
- CWEs: CWE-20, CWE-400, CWE-502, CWE-917
- Affected package: org.apache.logging.log4j:log4j-core (Maven)
- Vulnerable version range (as listed): >= 2.0-beta9, < 2.15.0 (first patched 2.15.0); >= 2.4.0, < 2.12.2 (patched 2.12.2); < 2.3.1 (patched 2.3.1); 2.12.3 also listed as a backport fix. Also lists org.ops4j.pax.logging:pax-logging-log4j2 and others.
- First fixed version: 2.15.0 (backports 2.12.2, 2.3.1, 2.12.3)
- Published: 2021-12-10; last updated 2025-10-22
- URL: https://github.com/advisories/GHSA-jfh8-c2jp-5v3q

### Follow-up advisories from the same December (patching just CVE-2021-44228 was not enough)

| CVE | GHSA | Severity | CVSS 3.1 | log4j-core vulnerable range | First fixed version |
|---|---|---|---|---|---|
| CVE-2021-45046 | GHSA-7rjr-3q55-vv33 | Critical | 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H) | >= 2.13.0, < 2.16.0; also >= 2.4.0 < 2.12.2 -> 2.12.2; < 2.3.1 -> 2.3.1 | 2.16.0 |
| CVE-2021-45105 | GHSA-p6xc-xr62-6r2g | High | 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H) | >= 2.4.0 < 2.12.3 -> 2.12.3; >= 2.13.0 < 2.17.0 -> 2.17.0; < 2.3.1 -> 2.3.1 | 2.17.0 |
| CVE-2021-44832 | GHSA-8489-44mv-ggj8 | Medium | 6.6 (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H) | >= 2.0-beta7 < 2.3.2 -> 2.3.2; >= 2.4 < 2.12.4 -> 2.12.4; >= 2.13.0 < 2.17.1 -> 2.17.1 | 2.17.1 |

Published dates: CVE-2021-45046 2021-12-14; CVE-2021-45105 2021-12-18; CVE-2021-44832 2022-01-04. All are type "reviewed". Summary: 45046 = incomplete 2.15.0 fix (MDC/context-lookup JNDI); 45105 = uncontrolled recursion DoS (fixed in 2.17.0/2.12.3); 44832 = JDBC Appender JNDI data-source name injection (fixed in 2.17.1/2.12.4/2.3.2).

## 2. xz-utils Backdoor — CVE-2024-3094 (March 2024)

### Who discovered it and how it was reported
- Andres Freund, a contributor to the Openwall oss-security mailing list, reported the backdoor on 29 March 2024 (message dated 08:51:26 -0700, subject "backdoor in upstream xz/liblzma leading to ssh server compromise"). He noticed odd symptoms (high sshd CPU, valgrind errors) on Debian sid and traced them to the upstream tarballs.
- The malicious code was solely in the distributed tarballs (present in 5.6.0 and 5.6.1), including extra .m4 files absent from the Git repository; the injected build-to-host.m4 extracts a prebuilt object file from test archives and modifies liblzma build output. Florian Weimer extracted the injected code for analysis.
- Impact observed: slowed ssh logins (SSD slowdown under specific env/argv conditions); the exploit targets x86-64 Linux with glibc/GCC and dpkg/rpm builds; likely works only where libsystemd loads liblzma (e.g. OpenSSH patched for systemd notification). Proposed impact: authentication bypass / possible RCE via hooking RSA_public_decrypt through the crc64_resolve IFUNC.

### What made it serious
- Supply-chain compromise rather than a coding bug: malicious code embedded in upstream tarballs, with the "fixes" themselves suspicious (commit dot-dot character disabling a build sandbox). Attribution pointed at maintainer Jia Tan; the account's real identity remained unclear; GitHub eventually archived the repo for ToS violation.
- Affected versions 5.6.0 and 5.6.1; fixed in 5.6.2; CISA recommends downgrade to 5.4.6 Stable. Impacted distros: Debian 13/unstable, Fedora Rawhide/40, Kali, OpenSUSE Tumbleweed; Arch urged prompt updates; FreeBSD unaffected (pre-incident versions).

### GitHub Advisory Database record (GHSA-rxwq-x6h5-x525)
- GHSA ID: GHSA-rxwq-x6h5-x525
- CVE: CVE-2024-3094
- Type: Unreviewed (the Malware-section filter returns no result; it is not classified as malware in the database, though CWE-506 "Embedded Malicious Code" applies)
- Severity: Critical
- CVSS 3.1: 10.0 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
- EPSS: 90.9% (100th percentile)
- CWE: CWE-506 (Embedded Malicious Code)
- Package/version: No package listed — "No package listed— Suggest a package"; affected and patched versions listed as "Unknown" (tarball-level issue, not a Maven/OS-package range)
- Published/updated: 2024-03-29
- URL: https://github.com/advisories/GHSA-rxwq-x6h5-x525

## 3. Upstream GitHub Issue Trackers

### Apache Log4j — repository is apache/logging-log4j2 (apache/log4j does not exist)
Issue search for "CVE-2021-44228" in apache/logging-log4j2 returned 1 result, but it is NOT about Log4Shell: #2833 "[MS24] Native Compilation Support #4" (closed/completed, 2024-11-10). Search for "CVE-2021-45046" returned 0 issues. The real tracking per the GHSA references lives in Apache JIRA: LOG4J2-3198, LOG4J2-3201, LOG4J2-3214, LOG4J2-3221 (https://issues.apache.org/jira/browse/). Pull requests that materially relate to the emergency fixes:
- #608 "Restrict LDAP access via JNDI" — merged 2021-12-05, author rgoers, 156 comments, 638 reactions. URL: https://github.com/apache/logging-log4j2/pull/608
- #633 "[possibly redundant] Completely disable JNDI in Interpolator.java, in the hope to patch CVE-2021-44228" — author SkySwimmer, closed 2021-12-16. URL: https://github.com/apache/logging-log4j2/pull/633
- #627 "2.12.1.sec1:Vulnerability fixed - based on 2.12.1 and supported Java7" — author quericy, closed 2021-12-14. URL: https://github.com/apache/logging-log4j2/pull/627

### xz-utils — repository is tukaani-project/xz
Issue search for "CVE-2024-3094" in tukaani-project/xz returned 3 issues:
- #103 "Response to backdoor incident" — closed/completed 2024-05-29, author thesamesam, 48 comments. URL: https://github.com/tukaani-project/xz/issues/103
- #92 "[Bug]: Upstream compromised? Or is the compromise?" — closed/not_planned 2024-04-07, author alerque, 77 comments. URL: https://github.com/tukaani-project/xz/issues/92
- #102 "[Feature Request]: please rewrite this library in rust" — closed/not_planned 2024-03-30, author jmwielandt, 6 comments. URL: https://github.com/tukaani-project/xz/issues/102

## 4. What This Means for Our Java/Linux Stack (Checklist)

- [ ] Java stack: if Log4j 2 is on the classpath, upgrade log4j-core to >= 2.17.1 (or 2.12.3 for the 2.12.x branch, 2.3.2 for 2.3.x). 2.15.0 and 2.16.0 are NOT sufficient for all three follow-up CVEs.
- [ ] Enable/verify log4j2.formatMsgNoLookups=true as a temporary mitigation (note: the GHSA says setting formatMsgNoLookups to true does NOT mitigate CVE-2021-45046).
- [ ] From 2.16.0+, JNDI is disabled by default and message lookups removed — prefer upgrading rather than relying on config tweaks.
- [ ] Linux stack: if xz-utils 5.6.0 or 5.6.1 is installed (or pulls it in via dependencies such as tools that bundle liblzma, e.g. sshd on some distros), downgrade to 5.4.6 Stable or newer (5.6.2+) and verify tarball signatures/checksums; rebuild affected packages from verified sources.
- [ ] Supply-chain hygiene: verify artifact signatures/checksums for critical transitive deps; prefer packages from distribution repos with signed updates over "latest from vendor" tarballs.
- [ ] Monitoring: alert on unexpected tarball diffs, unsigned builds, or unusual sshd CPU/behavior; EPSS for CVE-2024-3094 is 90.9%.
- [ ] Document the difference: Log4Shell = incomplete fix requiring a second release; xz = malicious code in tarballs (effectively an embedded-malicious-code case, CWE-506).

## 5. Sources

### Log4Shell
- Wikipedia — Log4Shell: https://en.wikipedia.org/wiki/Log4Shell
- Huntress Threat Library — CVE-2021-44228: https://www.huntress.com/threat-library/vulnerabilities/cve-2021-44228
- CVE.org Record — CVE-2021-44228: https://www.cve.org/CVERecord?id=CVE-2021-44228
- CrowdStrike — Log4j2 vulnerability analysis: https://www.crowdstrike.com/en-us/blog/log4j2-vulnerability-analysis-and-mitigation-recommendations
- Qualys — Is your web application exploitable by Log4Shell CVE-2021-44228: https://blog.qualys.com/vulnerabilities-threat-research/2021/12/15/is-your-web-application-exploitable-by-log4shell-vulnerability
- Splunk Research — Log4Shell CVE-2021-44228 analytics story: https://research.splunk.com/stories/log4shell_cve-2021-44228
- Apache Log4j Security Guide: https://logging.apache.org/log4j/2.x/security.html
- oss-security mailing list (2021-12-10 thread): http://www.openwall.com/lists/oss-security/2021/12/10/1
- NVD — CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- GitHub Advisory GHSA-jfh8-c2jp-5v3q: https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
- GitHub Advisory GHSA-7rjr-3q55-vv33 (CVE-2021-45046): https://github.com/advisories/GHSA-7rjr-3q55-vv33
- GitHub Advisory GHSA-p6xc-xr62-6r2g (CVE-2021-45105): https://github.com/advisories/GHSA-p6xc-xr62-6r2g
- GitHub Advisory GHSA-8489-44mv-ggj8 (CVE-2021-44832): https://github.com/advisories/GHSA-8489-44mv-ggj8

### xz backdoor
- CISA Alert — Reported Supply Chain Compromise Affecting XZ Utils, CVE-2024-3094: https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094
- oss-security mailing list (2024-03-29 thread, Andres Freund): https://www.openwall.com/lists/oss-security/2024/03/29/4
- Snyk — The XZ backdoor CVE-2024-3094: https://snyk.io/blog/the-xz-backdoor-cve-2024-3094
- Akamai — Critical Linux Backdoor in xz Utils: https://www.akamai.com/blog/security-research/critical-linux-backdoor-xz-utils-discovered-what-to-know
- Datadog Security Labs — XZ Utils backdoor (2024): https://securitylabs.datadoghq.com/articles/xz-backdoor-cve-2024-3094
- Red Hat — Urgent security alert for Fedora 41 and Rawhide users: https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users
- NVD — CVE-2024-3094: https://nvd.nist.gov/vuln/detail/CVE-2024-3094
- GitHub Advisory GHSA-rxwq-x6h5-x525: https://github.com/advisories/GHSA-rxwq-x6h5-x525
- xz repo issue #103: https://github.com/tukaani-project/xz/issues/103
- xz repo issue #92: https://github.com/tukaani-project/xz/issues/92
- xz repo issue #102: https://github.com/tukaani-project/xz/issues/102
