# blook-kdu VM lab — 2026-10-22 final-100 (superseded)

This directory is an **aborted partial run**, kept for provenance only.

- Command: `pwsh scripts/vm-lab.ps1 -All -TestSigning -Out docs/lab/20261022-final-100`
- Started 07:10:35 with a 100-id `kdu.exe`; the run process stopped while testing
  `dbutil23` at 07:17:27 and never wrote `matrix.md`. `matrix.json` contains the
  25 rows completed before the abort (23 PASS not yet reached).
- No VM state was lost: the guest was later reused by the final run.

## Partial numbers (25 rows)

| status | count |
| --- | --- |
| PASS | 3 (`adlice_rootlaser`, `amd_pdfwkrnl`, `atszio64`) |
| FAIL | 22 (`primitive-failed` 13, `device-open-failed` 5, `unparsed` 3, `driver-start-failed` 1) |
| CRASH | 0 |
| TIMEOUT | 0 |
| SKIP | 0 |

The `unparsed` rows were kill-only drivers (`appremover`, `bdapiutil`) plus
`astra64`: the harness at that time did not parse kdu's `SKIP` lines and did not
classify the user-mode `0xC0000005` exit. Both are fixed in `scripts/vm-lab.ps1`
(SKIP → status `SKIP`; exception exit → classification `kdu-crashed`).

## Authoritative results

See **`../20261022-final-108/README.md`** and `../20261022-final-108/matrix.json`
(108 ids: 23 PASS, 62 FAIL, 1 CRASH, 22 SKIP).
