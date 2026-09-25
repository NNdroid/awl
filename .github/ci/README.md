# Test CI configuration

The `.github/workflows/test.yml` workflow is intentionally self-contained.

## Required repository settings

No repository secrets, variables, or environments are required.

The workflow uses the automatically-created `GITHUB_TOKEN` with:

```yaml
permissions:
  contents: read
```

It runs on `push`, `pull_request`, and `workflow_dispatch`.

## Optional secrets

The following repository Actions secrets are optional. A fork with none of
them configured still runs unit tests, race tests, Linux NAT/NAT66 host-network
tests, Windows Wintun/WFP host-network tests, and build tests. The public
awl-tester e2e is supplemental and is skipped unless that platform has a
stable CI identity configured.

| Secret | Purpose |
| --- | --- |
| `CONFIG_AWL_LINUX` | Complete `config_awl.json` for a stable Linux CI peer identity |
| `CONFIG_AWL_MACOS` | Complete `config_awl.json` for a stable macOS CI peer identity |
| `CONFIG_AWL_WINDOWS` | Complete `config_awl.json` for a stable Windows CI peer identity |
| `CONFIG_LIBRESPEED` | Optional complete LibreSpeed `--local-json` server list override |

If a platform `CONFIG_AWL_*` secret is absent, the public awl-tester e2e for
that platform is skipped with a GitHub Actions notice. Core deterministic
coverage still runs.

If `CONFIG_LIBRESPEED` is absent and external e2e is enabled, CI uses
`.github/ci/librespeed.json`, which contains the public direct endpoint and
the AWL overlay endpoint.

## Public tester

The self-contained e2e helper connects to the public AWL test peer:

```text
name:    awl-tester
peer ID: 12D3KooWJMUjt9b5T1umzgzjLv5yG2ViuuF4qjmN65tsRXZGS1p8
mesh IP: 10.66.0.2
```

The public tester auto-accepts ordinary peer authentication, so the dedicated
throughput workflow can use an ephemeral CI identity to measure AWL overlay
performance without repository secrets. It does **not** grant arbitrary peers
exit-node permission.

The optional external e2e inside `test.yml` still uses stable
`CONFIG_AWL_*` identities when you want to exercise the pre-authorized public
tester path.

## Throughput benchmarks

Two workflows cover performance:

- `.github/workflows/throughput.yml` runs on Linux, Windows and macOS and takes
  three samples per path by default. It reports the median download/upload
  throughput, ping and jitter for:
  - direct public LibreSpeed traffic;
  - AWL overlay IPv4 to `10.66.0.2:8989`;
  - AWL overlay IPv6 to
    `[fd00:66:0:98ef:7a00:2b43:35a5:8524]:8989`.
- `.github/workflows/full-tunnel-throughput.yml` is fully self-contained. A
  temporary Linux runner starts an AWL gateway, creates a short-lived invite
  with `Allow as exit node`, and Linux/Windows clients benchmark direct
  traffic against system-wide full-tunnel traffic through that exit. No
  repository secrets are required.

macOS is intentionally absent from the full-tunnel matrix because AWL gateway
client mode is not supported on Darwin.

The public GitHub runners are not guaranteed to have public IPv6 egress, so
`throughput.yml` measures IPv6 on the AWL overlay itself. IPv6 full-tunnel
correctness/NAT66 is covered deterministically by the Windows Wintun/WFP,
gateway data-plane and Linux NAT66 host-network tests; the benchmark does not
claim public-internet NAT66 throughput unless the runner actually has public
IPv6.

All throughput workflows upload their JSON results and AWL logs as Actions
artifacts, and write the median result table to the GitHub Actions job summary.
