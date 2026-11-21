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
