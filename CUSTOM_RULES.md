# Custom HTTP detection rules

Enable **Load rule files** in Options and choose a folder, or use the default shown there. Each `.json`, `.yaml` or `.yml` file contains one rule. Files are loaded at the start of a scan; invalid files and duplicate IDs are skipped and explained in the activity log. Up to 256 files of 64 KiB each are loaded. Existing built-in checks remain active.

```yaml
id: example-test-header
name: Example application header exposed
severity: Low
cwe: 200
description: The application exposes its example header.
remediation: Remove the header if it is not required.
method: GET
path: /
status: 200
headerName: X-Example
headerContains: example
```

The same field names work in JSON. Required fields are `id`, `name`, `description`, `remediation`, and at least one of `bodyContains`, `bodyRegex`, `headerContains`, or `headerRegex`. `severity` defaults to `Info` and accepts `Info`, `Low`, `Medium`, `High`, or `Critical`; `cwe` defaults to 0. `method` defaults to GET and may be GET or HEAD. `path` defaults to `/` and must be a same-origin absolute path, optionally with a query string. Redirects are not followed. `status` is optional. Header matchers require `headerName`; body matchers require GET. All specified conditions must match. Contains checks and regular expressions are case-insensitive; regexes have a 100 ms match timeout. Bodies are limited to the first 256 KiB and decoded as UTF-8. Rules are passive read-only requests, share scan pacing and cancellation, and run against scanned virtual hosts. A finding includes the rule ID and response status, but not the response body or header value. Use unique names as well as unique IDs to avoid finding deduplication.

## Several paths, status lists and negative matches

A rule can try up to 16 paths with `paths` instead of `path`; it reports the first path that meets every condition, once per service. `statuses` lists up to 16 acceptable status codes and is combined with `status` when both are given. A rule may consist of a status condition alone, for example to flag a page that answers 200.

Negative conditions:

- `bodyNotContains`: the body must not contain the text (GET only).
- `headerNotContains`: the header named by `headerName` must not contain the text. A missing header counts as not containing it.
- `headerAbsent: true`: the header named by `headerName` must be missing. It cannot be combined with other header matchers.

```yaml
id: admin-console-open
name: Admin console reachable without sign-in
severity: High
cwe: 306
description: An administration page answers without asking for credentials.
remediation: Require authentication and restrict the console to the management network.
paths: [/admin/, /manage/, /console/]
statuses: [200]
bodyContains: dashboard
bodyNotContains: password
```

```yaml
id: missing-frame-options
name: Clickjacking protection header missing
severity: Low
cwe: 1021
description: The page can be framed by other sites.
remediation: Send X-Frame-Options or a frame-ancestors Content-Security-Policy.
method: HEAD
headerName: X-Frame-Options
headerAbsent: true
```

Rules run with the authentication headers configured for the host (Options > Engine > Authentication), so they can check pages behind a sign-in.

