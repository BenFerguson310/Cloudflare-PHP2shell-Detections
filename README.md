# php2shell (CVE-2026-109618 / CVE-2026-109619): Cloudflare WAF watch rule

A **Log-only** Cloudflare custom rule that shows whether a zone is being targeted by the php2shell PHP vulnerabilities. It adds visibility; it does not block anything and it does not replace patching PHP.

_Last updated: 2026-10-22_

## Background

- **What:** Two pre-authentication flaws in PHP core.
  - CVE-2026-109618: memory corruption when PHP runs out of memory while handling a request.
  - CVE-2026-109619: use-after-free across requests on the same worker, involving session upload progress.
- **Impact:** Remote code execution before application code runs. Researchers confirmed it against WordPress, Drupal, Joomla and Magento.
- **Affected:** PHP-FPM, mod_php, php-cgi, FrankenPHP and LiteSpeed. Fixed in **8.2.35, 8.3.36, 8.4.27 and 8.5.12** (released Oct 21, 2026). Older branches have source backports only or no fix.
- **Exploitation:** First seen Oct 17, 2026. Widespread by Oct 21, with payloads being changed to evade WAF signatures.

## Why a watch rule when Cloudflare already blocks it?

Cloudflare added 7 managed rules ("Generic Rules - Anomalous Execution - 1 to 7") to every plan. They run in the managed rules phase, which comes **after** custom rules. They never see a request when either of these happens first:

- An earlier custom rule (Block, challenge, bot rules) has already acted on it.
- A skip rule (an IP allowlist, partner bypass or header-based bypass) skips managed rules.

So "0 managed-rule hits" does not mean "not targeted". This rule sits at position #1, ahead of everything, and only logs.

## Expression (Enterprise)

```
(
  any(http.request.body.multipart.names[*][0] eq "PHP_SESSION_UPLOAD_PROGRESS")
  or any(http.request.body.form.names[*] eq "PHP_SESSION_UPLOAD_PROGRESS")
)
or (
  (
    http.request.uri.path contains ".php"
    or http.request.uri.path contains "/wp-"
    or any(http.request.uri.args.names[*] eq "rest_route")
  )
  and (
    http.request.headers.truncated
    or (not (http.request.method in {"GET" "HEAD" "OPTIONS"})
        and (http.request.body.truncated
             or starts_with(lower(http.request.headers["content-type"][0]), "multipart/")))
    or cf.waf.score.rce le 20
  )
)
```

| Condition | Why |
|---|---|
| `PHP_SESSION_UPLOAD_PROGRESS` field in the request body, anywhere | This is the mechanism PHP's interim fix for CVE-2026-109619 disables. Legitimate sites rarely send it. |
| Headers or body too large for Cloudflare to inspect, on PHP paths | Covers the memory-pressure route for CVE-2026-109618. Cloudflare inspects only the first 128 KB of a body on Enterprise. |
| Multipart POST, PUT or PATCH to PHP paths | Exploits arrive in the request body, and anonymous visitors seldom send multipart. |
| Cloudflare's RCE attack score of 20 or lower on PHP paths | Catches altered payloads that signatures miss. |

The PHP field name is matched with its exact capitalisation, as PHP itself does. Cloudflare's `lower()` cannot be applied to the nested multipart name list.

## Set the scope (the second block) for each zone

| Site | Scope block |
|---|---|
| Stack unknown, or mixed | Keep the default: `.php` paths, `/wp-` paths and WordPress's REST API (`rest_route`). |
| PHP served only under one path (for example a CMS at `/content/`) | Add `or starts_with(http.request.uri.path, "/content/")`. |
| Whole site is PHP (WordPress, Magento, Drupal) | Replace the scope block with `true`. Every page runs PHP, even URLs without ".php" in them. |
| Bot-detection sensor endpoint produces false RCE hits | Add `and not starts_with(http.request.uri.path, "/<sensor-path>")` to the `cf.waf.score.rce` line. |

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

## Requirements

- **Enterprise plan** with [attack score detection](https://developers.cloudflare.com/waf/detections/attack-score/) turned on. The body fields, `cf.waf.score.rce` and the Log action are all Enterprise-only.
- **Position #1**, ahead of every skip rule. Otherwise allowlisted traffic, or a forged bypass header, never reaches it.
- **Remove it once PHP is patched.** It's a temporary watch rule, not a permanent control.

## Reviewing hits

- **Security → Analytics → Events:** filter by rule name `PHP2SHELL WATCH - LOG`.
- Also filter on descriptions containing `Anomalous Execution`, which are Cloudflare's managed php2shell rules.
- For more detail, turn on [payload logging](https://developers.cloudflare.com/waf/managed-rules/payload-logging/) for the Cloudflare Managed Ruleset. It records the text that triggered each rule, encrypted with your own key, and needs a Super Administrator.

## Below Enterprise

Business, Pro and Free plans can't use a Log-only rule. Instead:

- Make sure the Cloudflare Managed Ruleset (paid plans) or Free Managed Ruleset is deployed, and in **Block** on paid plans.
- Watch Events for the `Anomalous Execution` rules.
- On Business, also filter Security Analytics on attack score class **Attack**.

## Limits

- **Traffic that skips Cloudflare isn't covered:** requests sent straight to the origin IP, or to a hostname that is DNS-only or served by another CDN. Lock the origin down to Cloudflare.
- **Body inspection stops at 128 KB.** Larger requests are caught by the "too large to inspect" condition, not by the field-name check.
- **Logging only.** It records attempts; it doesn't stop them.

## The fix

1. **Patch PHP** to 8.2.35, 8.3.36, 8.4.27 or 8.5.12, or your distribution's patched package.
2. **Interim mitigations** from the PHP project, which are partial only:
   - `session.upload_progress.enabled=0`
   - `memory_limit=-1`, enforced so applications can't override it
   - on PHP 8.5, `fatal_error_backtraces=0`
   - restart all PHP workers after changing these
3. **Check PHP logs since Oct 17, 2026** for:
   - out-of-memory errors ending `Unknown on line 0`
   - bursts of segfaults
   - PHP workers starting shell processes

## References

- [Cloudflare: protections against php2shell](https://blog.cloudflare.com/php-vulnerabilities-waf-protection)
- [Tenable: php2shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [watchTowr: CVE-2026-109618 FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [Safeguard: php2shell WAF rules and their limits](https://safeguard.sh/resources/blog/php2shell-waf-rules-stopgap-limits)
- [Cloudflare docs: request body fields](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.body.multipart.names/)
