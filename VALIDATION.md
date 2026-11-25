# Validation

The current payload was tested on 24 November 2026 in an AMD EPYC 9845 KVM guest executing native AVX-512/VBMI instructions. It used genuine JetBrains Docker distributions and a private, ordinary Git-backed TeamCity project. No CPU instruction emulator was involved.

| Component | Pin |
|---|---|
| TeamCity server | `2026.2.1`, build `239120` |
| Affected image | `jetbrains/teamcity-server@sha256:182dd71f30d8e085b3284fbc06c6c50d76eda8ecbcffae532f06a4ccd32ff0d5` |
| Additional TeamCity server | `2026.1.5`, build `222949` |
| Additional affected image | `jetbrains/teamcity-server@sha256:3dcdf2fd12b550e2a47d8c6da15e0f6e22c11cf88cfcd9628543f81ed7c61061` |
| Affected JVM | Amazon Corretto `21.0.10+7-LTS` |
| Fixed JVM | Amazon Corretto `21.0.13.1+2-LTS`, taken from the genuine republished TeamCity 2026.2.2 image |
| Fixed-JDK source image | `jetbrains/teamcity-server@sha256:2db18b4c24af1b3794a276523a093db7d7d4599afe5c83da3ac7e71ddbfb0845` |

The controlled cases used TeamCity 2026.2.1 and the same generated Kotlin source revision, with separate copies of a stopped application data volume. The real DSL children were observed externally with `jcmd`. The affected and fixed children had the Base64 intrinsic enabled; every observed disabled child had `UseBASE64Intrinsics=false` on its actual command line.

| Application case | Observed result |
|---|---|
| Affected Corretto 21.0.10 | The ordinary subprocess was denied. The bounded decoder probe observed the exact 62-byte overwrite, then the array-length witness changed to `-1700370022`. The supplied shell command returned exactly `teamcity-streams:a"b$c\d\n1000\n` on stdout, `teamcity-stderr\n` on stderr, and exit `7`. A subprocess was denied again after restoration. |
| Same runtime, intrinsic disabled | Bounded decoder probe unchanged; no heap edit or command result. The public helper returned `1` with empty stdout. |
| Same TeamCity product, genuine fixed Corretto | Bounded decoder probe unchanged; no heap edit or command result. The public helper returned `1` with empty stdout. |

The Python client accepted the affected result with exit `0`; the target's exit status is separate. The three controlled server runs stopped normally with exit `0` and no Docker OOM event. The tested source and generated request matched the local candidate byte for byte.

A second three-runtime comparison used genuine TeamCity 2026.1.5. Its shipped Java executable and `libjvm` matched the original 2026.2.1 Corretto binaries, and its stock DSL security-agent gate class was identical. The public client prepared the `2026.1.5` profile, and the same settings revision reached all three cases. The affected case returned exactly `1000\n`, empty target stderr, exit `0`, and the restored subprocess denial. Both controls returned `UNCHANGED_DECODER_PROBE`, with client exit `1` and empty stdout. The actual DSL children had the expected runtime and intrinsic flags. The disabled and fixed containers exited `0`; the affected container exited `1` after its stock launcher reported a missing Catalina PID file. All six recorded DSL process identities and all processes in the three stopped container cgroups were absent. No fatal JVM logs were found. This comparison used the setup administrator; it does not establish restricted-account collection on 2026.1.5.

## Native reliability sample

The reviewed 2026.2.1 client and heap payload were frozen before a fixed sample of 15 new `id -u` requests. Each used a fresh request ID and an ordinary VCS import. The client did not retry a failed attempt.

| Sample | Exact command results | Misses |
|---|---:|---:|
| One request after each of five fresh TeamCity server starts | 5 / 5 | 0 |
| Ten further imports on the fifth server | 10 / 10 | 0 |

Every accepted result contained exactly `1000\n`, empty target stderr, exit `0`, and the restored subprocess denial. The repeated imports used fresh DSL generator JVMs, so this measures server reuse rather than repeated exploitation of one surviving DSL JVM. Reconciliation matched the request sources, real Corretto version and effective intrinsic flags. All 17 observed DSL process identities were absent afterward; the five measured server shutdowns exited `0`, and no fatal JVM logs were found. These results cover one CPU, product build, runtime and command. They do not establish a general reliability percentage.

## Additional checks

Two additional imports exercised failure handling in the real affected DSL process. A missing executable returned `COMMAND_ERROR` with the original `IOException`, a restored gate, and a fresh subprocess denial; the public client returned `1` with empty stdout. A command writing continuously to both streams timed out, returned exit `137`, and captured exactly 65,536 bytes per stream with truncation reported. Its recorded process identity was gone, and the sandbox denied a subprocess again.

The three affected imports arrived through ordinary VCS synchronization. Their public clients used the stock Project Viewer role scoped to the test project, with per-project authorization enabled and no inherited developer role. The account could read the project but received `403` for reading versioned-settings configuration/status, changing those settings, explicitly loading settings, and reading server authentication settings. The setup account configured the project and roles beforehand. This establishes the tested read-only collection route; the operator still needs independent write access to the settings repository. JetBrains documents the [authorization modes and roles](https://www.jetbrains.com/help/teamcity/managing-roles-and-permissions.html).

Nine focused command checks passed using the real compiled payload, JetBrains' bundled Kotlin compiler, and the genuine fixed Corretto JDK. They covered exact streams and exit status, stdin EOF, both sides of the output-size boundary, continuous-output timeout, missing executables, interruption, and preservation of cleanup errors. Nine focused client regressions and the existing owned-loopback HTTP checks passed on Python 3.12.3. They covered both product profiles, literal template-like command arguments, exact output and target status, missing restoration evidence, changed request files, malformed input, and the narrow `--wait-only` permission fallback. The current generator also reproduced the saved application payloads byte for byte for both product comparisons and all 15 reliability attempts. The HTTP fixtures validate client behavior; they are not application exploit evidence.

A genuine TeamCity 2026.2.2 preflight returned `77`. Other layouts, agent-side DSL execution, concurrent requests, and arbitrary process trees remain untested.

## Reproducing the controls

Use the affected image on an eligible x86-64 host, configure an ordinary Git-backed Kotlin project with `dslExecutionMode=sandbox`, and load the generated settings. Keep the affected, disabled, and fixed cases on separate data volumes. Use the same settings revision and command in each case.

For the disabled case, the server JVM flag alone does not cover the separate DSL generator. In the tested TeamCity build, its real JVM argument property is:

```properties
teamcity.versionedSettings.configsGeneratorJvmArgs=-XX:-UseBASE64Intrinsics
```

Set it in the case's TeamCity `config/internal.properties`, restart that case, and verify the running `DslGeneratorProcess` with `jcmd <pid> VM.flags -all`. An earlier attempt to pass `JAVA_TOOL_OPTIONS` through the parent produced a child with the intrinsic still enabled. That attempt is excluded from the mitigation result.

For the fixed control, run the same TeamCity product with a genuine vendor-fixed JDK and verify the DSL child's `VM.version`. JetBrains lists the fixed Corretto versions in its [advisory](https://blog.jetbrains.com/teamcity/2026/11/java4shell-cve-2026-114938-what-it-means-for-teamcity/).

Separate testing established anonymous decoder corruption and bounded heap disclosure in stock TeamCity 2026.2.1, with intrinsic-disabled and genuine fixed-runtime controls. That research has not produced HTTP command execution. This repository ships the Kotlin DSL sandbox escape described above.

The credentials, raw responses, process records, diagnostic tooling, and runtime files are retained privately. They are excluded from this repository's intended export.
