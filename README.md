# Java4Shell: TeamCity Kotlin DSL sandbox escape

This Rapid7 research PoC uses CVE-2026-114938 to escape TeamCity's server-side Kotlin DSL sandbox and execute a supplied operating-system command. Rapid7's [Emergent Threat Response article](https://www.rapid7.com/blog/post/etr-cve-2026-114938-reported-critical-pre-authentication-remote-code-execution-java-17/) covers the vulnerability and mitigation guidance.

**Required access and configuration:** you must be able to change the Git repository that an existing TeamCity project uses for its versioned Kotlin settings. That project must execute the settings in the **server-side sandbox**. An administrator must have configured this integration beforehand. The PoC does not establish unauthenticated RCE or apply automatically to a fresh TeamCity installation.

The tested targets are TeamCity **2026.2.1** (build 239120) and **2026.1.5** (build 222949), with their original bundled Amazon Corretto 21.0.10 JVM on Linux x86-64 with native AVX-512 VBMI support. `exploit.py` prepares the settings and reads the result. The actual exploit is in [payload/HeapEscape.kt](payload/HeapEscape.kt), called by [payload/settings.kts.in](payload/settings.kts.in). See [VALIDATION.md](VALIDATION.md) for the genuine runtime controls and test results.

## Use

Use Python 3.10 or later and an empty, disposable TeamCity project. In **Project Settings → Versioned Settings**, the format must be Kotlin and synchronization must be enabled. On 2026.2, execution must already be set to the server sandbox. The tested 2026.1.5 release has no agent-execution selector. The helper does not change the project's configuration.

Generate a new settings directory for the command:

```bash
python3 exploit.py prepare \
  --url https://teamcity.example.test \
  --profile 2026.2.1 \
  --output /path/to/owned-settings-repository/.teamcity \
  -- /usr/bin/id -u
```

Use `--profile 2026.1.5` for build 222949. The output directory must not already exist. The generated files define a complete, minimal project, so do not use them to replace existing build definitions. Commit them to the project's configured settings repository. Keep `request.json` for result collection.

Place a TeamCity API token in a private file, then load the settings and collect the result:

```bash
python3 exploit.py run \
  --url https://teamcity.example.test \
  --project Java4ShellDsl \
  --request /path/to/owned-settings-repository/.teamcity/request.json \
  --token-file /path/to/private-token.txt \
  --wait-only
```

This waits for TeamCity's normal VCS synchronization. The command's stdout is written directly to local stdout; target stderr and the result line go to local stderr. The recorded command returned UID `1000`, which is specific to the tested container:

```text
1000
[teamcity-poc] target exit=0 timeout=false truncated=false
```

On 2026.2.1, `--wait-only` was tested with the stock Project Viewer role scoped to the project. It can collect the result even when the configuration and status APIs return `403`. The 2026.1.5 comparison used an administrator; restricted-account collection remains untested there. Omit `--wait-only` to request an explicit reload, which requires permission to edit the project and load its settings. Alternatively, `--credentials-file` accepts a private JSON file containing `username` and `password`.

The helper exits `0` for a complete result, `1` for a failed, missed or incomplete result or invalid input data, `2` for CLI syntax errors, and `77` for an unsupported target, configuration or argument encoding. The target's exit status is reported separately. `--socket-timeout` controls each HTTP socket; `--wait` limits result polling.

Commands receive closed stdin and at most 64 KiB of captured output per stream. A five-second deadline starts after process creation. On timeout, the payload forcibly stops the direct child and waits up to two seconds for termination. Interactive shells and arbitrary process trees are unsupported. Arguments that the DSL child's native encoding cannot represent are rejected before the heap edit.

## How it works

The payload first confirms that the stock sandbox rejects a harmless subprocess. It warms the decoder and requires the genuine 62-byte overwrite to appear inside an oversized destination array. A second malformed decode then corrupts an adjacent integer-array header. The resulting heap access repairs that header, temporarily changes the DSL security agent's gate, executes the supplied command, and restores the gate. A fresh subprocess must be denied afterward. The payload does not require a security-agent replacement, Unsafe call, native helper or startup relaxation.

## Scope

The heap layout is pinned to the tested Corretto builds. A sample of 15 native attempts on 2026.2.1 produced 15 exact command results on one environment. That is not a general success rate. An unchanged decoder or array witness is a failed attempt, not proof that another runtime is fixed. Other versions, vendors, layouts, Windows targets and concurrent use remain untested. The restoration checks do not establish that every failure path leaves the DSL JVM reusable; use disposable instances for comparisons.

TeamCity 2026.2 recommends agent-side DSL execution. That mode already permits ordinary build commands and is outside this PoC's claim. See JetBrains' [Kotlin DSL documentation](https://www.jetbrains.com/help/teamcity/kotlin-dsl.html).

Calif disclosed [Java4Shell](https://calif.io/java4shell/), and OpenJDK integrated the fix as [JDK-8393212](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b). JetBrains' [advisory](https://blog.jetbrains.com/teamcity/2026/11/java4shell-cve-2026-114938-what-it-means-for-teamcity/) identifies a potential exploitation scenario without disclosing its route. This repository independently demonstrates the Kotlin DSL sandbox escape; it does not establish that JetBrains used the same route.
