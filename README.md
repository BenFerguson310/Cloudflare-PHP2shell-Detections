# php2shell (CVE-2026-109618 / CVE-2026-109619): Cloudflare WAF watch rule

A **Log-only** Cloudflare custom rule that shows whether a zone is being targeted by the php2shell PHP vulnerabilities. It adds visibility; it does not block anything and it does not replace patching PHP.

_Version 2 · Last updated: 2026-10-22 17:30 UTC_

## Background

- **What:** Two pre-authentication flaws in PHP core.
  - CVE-2026-109618: memory corruption when PHP runs out of memory while handling a request.
  - CVE-2026-109619: use-after-free across requests on the same worker, involving session upload progress.
- **Impact:** Remote code execution before application code runs. Researchers confirmed it against WordPress, Drupal, Joomla and Magento.
- **Affected:** PHP-FPM, mod_php, php-cgi, FrankenPHP and LiteSpeed. Fixed in **8.2.35, 8.3.36, 8.4.27 and 8.5.12** (released Oct 21, 2026). Older branches have source backports only or no fix.
- **Exploitation:**
  - First seen Oct 17, 2026, four days before disclosure.
  - Cloudflare reported attempts rising from tens of thousands in the first 45 minutes after disclosure to millions.
  - Several scanner and exploit tool families are active, and payloads are being changed to evade WAF signatures.

## Why a watch rule when Cloudflare already blocks it?

Cloudflare's 7 managed rules for this flaw (now named "PHP Remote Code Execution Attack (CVE-2026-109618, CVE-2026-109619) #1 to #7") run in the managed rules phase, which comes **after** custom rules. They never see a request when either of these happens first:

- An earlier custom rule (Block, challenge, bot rules) has already acted on it.
- A skip rule (an IP allowlist, partner bypass or header-based bypass) skips managed rules.

They also only catch exploit attempts, not the reconnaissance scans that come first. So "0 managed-rule hits" does not mean "not targeted". This rule sits at position #1, ahead of everything, and only logs.

## Expression (Enterprise)

```
(any(http.request.body.multipart.names[*][0] in {"PHP_SESSION_UPLOAD_PROGRESS" "wafjunk"})
 or any(http.request.body.form.names[*] in {"PHP_SESSION_UPLOAD_PROGRESS" "wafjunk"})
 or http.request.body.raw contains "PHP_SESSION_UPLOAD_PROGRESS"
 or http.request.body.raw contains "JACKALPOC"
 or http.request.body.raw contains "PWNED::"
 or http.request.body.raw contains "<?php"
 or any(http.request.body.multipart.filenames[*][0] in {"p2s.txt" "uga67qBl6ky1.txt"})
 or any(http.request.body.multipart.names[*][0] matches "(\\[[^\\]]*\\]){4,}")
 or any(http.request.body.form.names[*] matches "(\\[[^\\]]*\\]){4,}")
 or len(http.request.body.multipart.names) gt 100
 or lower(http.request.headers["content-type"][0]) contains "p2s"
 or lower(http.request.headers["content-type"][0]) contains "chkbnd"
 or lower(http.user_agent) contains "php2shell"
 or starts_with(http.user_agent, "B8RAT/")
 or http.cookie contains "xqsuvwz3n97wu8j3emz1axuo5y"
 or lower(url_decode(http.request.uri.query)) contains "php://filter"
 or ip.src in {103.216.220.92 31.223.184.166 37.19.200.5 134.209.159.64 103.114.163.188 95.217.98.37 85.11.167.243 45.198.224.169 109.71.252.97 221.14.159.134 91.90.123.25 94.154.43.7 38.180.45.91 80.66.66.66 217.60.242.76 87.192.237.19 34.19.34.88 34.76.232.95 34.76.218.47 92.118.112.100 194.42.196.44 182.10.137.175}
)
or (not (http.request.method in {"GET" "HEAD" "OPTIONS"})
 and (http.request.body.truncated
  or (starts_with(lower(http.request.headers["content-type"][0]), "multipart/")
      and (len(http.request.headers["content-length"]) eq 0
           or lower(http.request.headers["transfer-encoding"][0]) contains "chunked"))
  or (http.request.uri.path in {"/" "/index.php"} and http.user_agent eq "")))
or ((http.request.uri.path contains ".php"
  or http.request.uri.path contains "/wp-"
  or any(http.request.uri.args.names[*] eq "rest_route"))
 and (http.request.headers.truncated
  or (not (http.request.method in {"GET" "HEAD" "OPTIONS"})
      and starts_with(lower(http.request.headers["content-type"][0]), "multipart/"))
  or cf.waf.score.rce le 20))
```

About 2,100 characters, well under Cloudflare's 4,096-character limit. This is the same expression that passed Cloudflare's parser on a production Enterprise zone, minus that zone's site-specific lines.

### What each part catches

**Anywhere on the zone (exploit and tool signatures)**

| Condition | Why |
|---|---|
| `PHP_SESSION_UPLOAD_PROGRESS` as a form or multipart field, or anywhere in the raw body | The CVE-2026-109619 trigger. The raw-body check also catches malformed uploads Cloudflare can't parse into fields. |
| `wafjunk` field | Padding used by a WAF-bypass group (bodies of about 1 MB of repeated "A"). |
| `JACKALPOC`, `PWNED::`, `<?php` in the body | A test string used to confirm code execution, the planted web shell (`<?php echo 'PWNED::'; system($_GET['c']); ?>`), and PHP code injected through the session. |
| Filenames `p2s.txt`, `uga67qBl6ky1.txt` | Upload filenames seen in exploit requests. |
| Field names nested 4 or more levels deep | Exploits nest field names dozens to hundreds of levels deep. |
| More than 100 multipart parts | Scanner bodies carry 149+ filler parts. |
| `p2s` or `CHKBND` in the Content-Type boundary | Boundaries such as `----p2shell<hex>`, `------p2s9rdme2st6guc9g0rafic` and `CHKBND`. |
| User agent containing `php2shell`, or starting with `B8RAT/` | `php2shell-scan/109618`, `php2shell-scan/1.3`, `php2shell-scan/2.0`, `php2shell-verify/1.0`, `Mozilla/5.0 (php2shell-poc)`, `B8RAT/1.0`. |
| Session ID `xqsuvwz3n97wu8j3emz1axuo5y` | The session used to plant the web shell. |
| `php://filter` in the query string | Follow-up requests that read the web shell's output. |
| Listed IPs | Published sources of exploit and scan traffic (see IOCs below). |

**Any non-GET request**

| Condition | Why |
|---|---|
| Body too large for Cloudflare to inspect (over 128 KB) | Memory-pressure bodies and padding meant to hide a payload past the inspection limit. |
| Multipart with no Content-Length, or chunked | Exploits send chunked multipart bodies; real browsers send a Content-Length. |
| POST to `/` or `/index.php` with no user agent | Short follow-up requests after a web shell is planted. |

**PHP and WordPress paths only**

| Condition | Why |
|---|---|
| Headers too large to inspect | The CVE-2026-109618 vector packs many headers into one part. |
| Any multipart POST, PUT or PATCH | Anonymous visitors seldom send multipart. |
| Cloudflare's RCE attack score of 20 or lower | Catches altered payloads that signatures miss. |

PHP field names are matched with their exact capitalisation, as PHP itself does. Cloudflare's `lower()` cannot be applied to the nested multipart name list.

## Set the scope (the last block) for each zone

| Site | Scope block |
|---|---|
| Stack unknown, or mixed | Keep the default: `.php` paths, `/wp-` paths and WordPress's REST API (`rest_route`). |
| PHP served only under one path (for example a CMS at `/content/`) | Add `or starts_with(http.request.uri.path, "/content/")`. |
| Whole site is PHP (WordPress, Magento, Drupal) | Replace the scope block with `true`. Every page runs PHP, even URLs without ".php" in them. |
| Bot-detection sensor endpoint produces false RCE hits | Change the last line to `or (cf.waf.score.rce le 20 and not starts_with(http.request.uri.path, "/<sensor-path>"))`. |
| Site legitimately accepts large or chunked uploads | Add `and not starts_with(http.request.uri.path, "/<upload-path>")` to the "any non-GET" block, or expect some noise. |

## Indicators of compromise

The IPs are mostly shared anonymiser and hosting infrastructure. Use them to find related activity; don't block them outright.

| Indicator | Type | Source |
|---|---|---|
| 103.216.220.92, 31.223.184.166, 37.19.200.5, 134.209.159.64, 103.114.163.188, 95.217.98.37 | IP | Amazon MadPot honeypots, Oct 17 and 21 |
| 85.11.167.243, 45.198.224.169, 109.71.252.97, 221.14.159.134, 91.90.123.25 | IP | VulnCheck sensors, Oct 21 |
| 94.154.43.7, 38.180.45.91, 80.66.66.66, 217.60.242.76, 87.192.237.19, 34.19.34.88, 34.76.232.95, 34.76.218.47 | IP | OffSeq honeypot fleet, Oct 20 to 22 |
| 194.42.196.44 | IP | OffSeq; possibly related, not confirmed |
| 182.10.137.175 | IP | `php2shell-scan/2.0` reconnaissance seen in production, Oct 22 |
| 92.118.112.100 (`http://92.118.112.100/nfs`) | IP / URL | Second-stage binary download (ELLIO) |
| `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` | SHA-256 | Second-stage ELF binary (ELLIO) |
| `JACKALPOC` | String | Test string used to confirm code execution |
| `PWNED::` | String | Output of the planted web shell |
| `sess_xqsuvwz3n97wu8j3emz1axuo5y` | File | Session file holding the web shell |

## Deploy (API)

Save the expression to `php2shell.expr`, then run:

```bash
RS=$(curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq -r .result.id)

jq -n --rawfile e php2shell.expr \
  '{description:"PHP2SHELL WATCH - LOG",action:"log",enabled:true,position:{index:1},expression:$e}' |
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/$RS/rules" \
  -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data @- | jq '.success,.errors'
```

- The API token needs **Zone > Zone WAF > Edit**.
- If the zone has no custom rules yet, the entrypoint lookup fails. Create the first rule in the dashboard, or `PUT` the phase entrypoint instead.
- Check the output reads `true` with no errors; the API rejects expressions that don't parse.
- **Upgrading from version 1:** `PATCH` the existing rule (`/rulesets/$RS/rules/$RULE_ID`) with the same body minus `position`, so it keeps position #1.

## Requirements

- **Enterprise plan** with [attack score detection](https://developers.cloudflare.com/waf/detections/attack-score/) turned on. The body fields, `matches`, `cf.waf.score.rce` and the Log action are all Enterprise-only.
- **Position #1**, ahead of every skip rule. Otherwise allowlisted traffic, or a forged bypass header, never reaches it.
- **Remove it once PHP is patched.** It's a temporary watch rule, not a permanent control.

## Reviewing hits

- **Security → Analytics → Events:** filter by rule name `PHP2SHELL WATCH - LOG`.
- **Cloudflare's managed rules:** filter on descriptions containing `PHP Remote Code Execution Attack`. Cloudflare renamed them on Oct 22; they were "Generic Rules - Anomalous Execution - 1 to 7". Rule IDs did not change:
  - Managed Ruleset: `c1d409ad838f47f59446f21cc438d5dd`, `f9a45927414245e3a64bb12d0a0c2f64`, `771c654ae1154d4daa72f4e1545d163c`, `217005865f0145f392300bac212afcc9`, `38efdb17ea594501bb55a1d71867b12e`, `4148ae686fdb4d01be673fab9d9c073d`, `1389aa259617437392ce149c48143645`
  - Free Ruleset: `4e315666e8e344cdb64119a3b5ccf32f`, `00c10e6cc4da4bd08722adeebcd95984`, `48ddf592361e4fdb97a8a85982dab691`, `3556683d512a47f2937899c524b1a4c6`, `da07c85852e34625bb478496302ede46`, `19373a83abb840e18ab3ce5a7975ce1b`, `07f0b6ddaabf40b1b2042dade8d613fa`
- **Scans the rule won't flag:** `php2shell-scan/2.0` first requests pages that reveal the PHP version (`/phpinfo.php`, `/info.php`, `/test.php`, `/composer.json`, `/vendor/composer/installed.json`, `/phpunit.xml`). The user agent condition catches it; the path list alone is common scanner noise.
- For more detail, turn on [payload logging](https://developers.cloudflare.com/waf/managed-rules/payload-logging/) for the Cloudflare Managed Ruleset. It records the text that triggered each rule, encrypted with your own key, and needs a Super Administrator.

## Below Enterprise

Business, Pro and Free plans can't use a Log-only rule. Instead:

- Make sure the Cloudflare Managed Ruleset (paid plans) or Free Managed Ruleset is deployed, and in **Block** on paid plans.
- Watch Events for the `PHP Remote Code Execution Attack` rules (or the rule IDs above).
- On Business, also filter Security Analytics on attack score class **Attack**.

## Limits

- **Traffic that skips Cloudflare isn't covered:** requests sent straight to the origin IP, or to a hostname that is DNS-only or served by another CDN. Lock the origin down to Cloudflare.
- **Body inspection stops at 128 KB.** Larger requests are caught by the "too large to inspect" condition, not by the field-name checks.
- **Body checks can't be backtested.** Cloudflare analytics don't store request bodies, so those conditions only show hits from the moment the rule is live.
- **Signatures go stale.** User agents, boundaries, filenames and IPs are trivial for attackers to change; the structural checks (nesting, part count, oversized and chunked bodies) last longer.
- **Logging only.** It records attempts; it doesn't stop them.

## The fix

1. **Patch PHP** to 8.2.35, 8.3.36, 8.4.27 or 8.5.12, or your distribution's patched package.
2. **Interim mitigations** from the PHP project, which are partial only:
   - `session.upload_progress.enabled=0`
   - `memory_limit=-1`, enforced so applications can't override it
   - on PHP 8.5, `fatal_error_backtraces=0`
   - restart all PHP workers after changing these
3. **Check servers since Oct 17, 2026** for:
   - PHP log lines containing `Allowed memory size of`, `Out of memory (allocated` or `Unknown on line 0`
   - bursts of segfaults (`exited on signal 11`)
   - PHP workers starting `sh`, `bash`, `curl` or `wget`
   - session files named `sess_xqsuvwz3n97wu8j3emz1axuo5y`, and unexpected executables in `/tmp`

## Changelog

- **v2 (2026-10-22):**
  - Added detections for the raw request body, `wafjunk` padding, the `JACKALPOC`, `PWNED::` and `<?php` strings, and the exploit filenames.
  - Added checks for deep field-name nesting, 100+ multipart parts, and p2s/CHKBND boundaries.
  - Added chunked or lengthless multipart, oversized POSTs anywhere on the zone, and empty-user-agent POSTs to `/`.
  - Added the `php2shell` and `B8RAT/` user agents, the planted session ID, `php://filter`, and the IOC IPs.
  - Updated the names of Cloudflare's managed rules.
- **v1 (2026-10-22):** First release.

## References

- [Cloudflare: protections against php2shell](https://blog.cloudflare.com/php-vulnerabilities-waf-protection)
- [Amazon Threat Intelligence: PHP2Shell exploitation before disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [VulnCheck: PHP2Shell vulnerabilities](https://www.vulncheck.com/blog/php2shell-vulnerabilities)
- [ELLIO: PHP2Shell, what we observed](https://ellio.tech/en/blog/php2shell-what-we-observed-and-what-to-do/)
- [OffSeq: the first 48 hours on a honeypot fleet](https://offseq.com/en/research/php2shell-first-48-hours/)
- [Prophet Security: detecting and investigating php2shell](https://www.prophetsecurity.ai/blog/php2shell)
- [Tenable: php2shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [Cybernews: PHP2Shell attempts hit millions](https://cybernews.com/security/php2shell-wordpress-amazon-cloudflare-ai-cyberattacks/)
- [Cloudflare WAF emergency release, 2026-10-21](https://developers.cloudflare.com/changelog/post/2026-10-21-emergency-waf-release-cfmr/)
- [Cloudflare docs: request body fields](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.names/)
