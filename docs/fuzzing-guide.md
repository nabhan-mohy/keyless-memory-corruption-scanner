# Fuzzing with KMCS

This guide is written for a security researcher who has just cloned KMCS and
wants to find bugs in a C or C++ library. It documents what we learned while
building and testing the tool, including three traps that cost us most of a
day and every one of which produced the same symptom: *"the fuzzer found
nothing."*

## Before you start

You must have **written authorisation** to fuzz the target. Fuzzing is
indiscriminate; running a campaign against software you do not own is a
legal risk in most jurisdictions.

## Quick start with Docker

The fastest way to see KMCS work end to end is a container. Debian 12 is
used because ASan's shadow-memory reservation works reliably inside it.

```bash
git clone https://github.com/nabhan-mohy/keyless-memory-corruption-scanner
cd keyless-memory-corruption-scanner
docker compose build
docker compose run --rm kmcs python scripts/demo_campaign.py
```

The demo builds a small C target, verifies it crashes on a specific input,
runs a 10-second AFL++ campaign, and prints the findings and report paths.
It exits 0 on success.

To run the full test suite inside the container:

```bash
docker compose run --rm kmcs python -m pytest tests -m "not integration" -q
docker compose run --rm kmcs python -m pytest tests/integration -q -m integration
```

## The three traps

Every one of these produces the same symptom — *"AFL++ ran N executions and
found no crashes"* — and every one has a different fix.

### Trap 1 — the target crashes on every input

Fuzzers work by starting from a benign seed, mutating it, and watching for
crashes. A target that crashes on every input gives the fuzzer no benign
baseline. AFL++ detects this during its dry-run and refuses to start:

```
[-] PROGRAM ABORT : We need at least one valid input seed that does not crash!
```

The fix is to make the target crash *only* when a specific byte or sequence
appears.

```c
#include <stdio.h>
#include <stdlib.h>

int *buggy_pointer;

int main(void) {
    int c;
    int trigger = 0;
    while ((c = getchar()) != EOF) {
        if (c == '!') {
            trigger = 1;
        }
    }
    if (!trigger) {
        return 0;
    }
    return *buggy_pointer;   /* crash only when the input contains '!' */
}
```

The seed `"x"` runs cleanly. AFL++ mutates it to contain `'!'`, and the
crash appears in seconds.

### Trap 2 — the compiler optimises the bug away

At `-O1` and above, the compiler is allowed to do *anything* with undefined
behaviour. `*NULL` is undefined. So the compiler may replace the null
dereference with a trap, a return, or nothing at all. The binary then runs
to completion and exits 0 — a fuzzer cannot find a bug that has been
removed from the machine code.

The fix is to make the compiler unable to prove the pointer is NULL. Read
it from an `extern` global that is never assigned in this translation unit:

```c
int *buggy_pointer;   /* external linkage, no initialiser here */

int main(void) {
    int c = getchar();
    if (c == EOF) {
        return 0;
    }
    return *buggy_pointer;   /* the compiler must load the pointer */
}
```

`volatile` alone is not enough — we tried. The `extern` global pattern is
what reliably defeats the optimiser at `-O1`.

### Trap 3 — the sanitizer is not detecting anything

On some container images (Kali is one), AddressSanitizer cannot reserve its
shadow memory at startup. It prints a message like:

```
==...==ERROR: AddressSanitizer failed to allocate 0xdfff0001000 bytes
==...==ReserveShadowMemoryRange failed while trying to map ...
```

and then the process exits 0 without running the target. From the researcher's
point of view this looks exactly like Trap 2 — a crash that never happens.

**Verify ASan works before trusting any campaign result.** Compile a trivial
ASan probe and confirm it crashes:

```bash
cat > /tmp/asan_probe.c <<'EOF'
#include <stdlib.h>
int main(void) {
    char *p = (char *)malloc(8);
    p[100] = 'A';
    return 0;
}
EOF
clang -g -O0 -fsanitize=address /tmp/asan_probe.c -o /tmp/asan_probe
/tmp/asan_probe
echo "exit: $?"
```

If the exit code is 0, ASan is not working on this system. Run KMCS inside
the Docker container we provide; that is a known-good environment.

## Building a fuzzable target with ASan

Once ASan works, the build command for a coverage-instrumented target is:

```bash
AFL_USE_ASAN=1 afl-clang-lto -g -O1 -fno-omit-frame-pointer target.c -o target_afl
```

Note there is no `-fsanitize=address` on the command line. AFL++ adds it
internally when `AFL_USE_ASAN=1` is set. Adding the flag twice causes
linking problems.

Verify the target:

```bash
printf 'benign' | ./target_afl
echo "benign exit: $?"    # must be 0

printf '!!!!!' | ./target_afl
echo "trigger exit: $?"   # must be non-zero
```

Both checks must pass. If the benign check returns non-zero, either the
target has a bug that runs on every input (Trap 1) or ASan is not
initialising properly (Trap 3). Do not proceed to a campaign until both
are correct.

## Registering a target

```bash
kmcs target add mylib \
    --executable /path/to/target_afl \
    --compiler clang \
    --build-configuration asan \
    --sanitizer address
```

The `--build-configuration` and `--sanitizer` fields are metadata that
record how the target was built. They do not modify the binary; they tell
KMCS's crash classifier what to expect.

## Assembling a corpus

A corpus is a set of seed inputs. Every seed must be benign — it must not
crash the target. If even one seed crashes, AFL++ refuses to run.

```bash
mkdir seeds
printf 'x' > seeds/seed    # benign — does not contain the trigger
kmcs corpus create mylib-seeds --target <target-id>
kmcs corpus add mylib-seeds seeds/seed
```

A corpus of a single benign seed is enough for a target that crashes on a
short trigger. For a real-world library, gather a handful of valid examples
of the input format the library parses.

## Running a campaign

```bash
kmcs campaign create mylib-run \
    --target <target-id> \
    --corpus <corpus-id> \
    --fuzzer afl++ \
    --sanitizer address \
    --workers 2 \
    --duration-seconds 300

kmcs campaign start mylib-run
```

`kmcs campaign start` accepts the campaign id or name. The target binary
and corpus directory are read from the records already in the database.
Use `--target-binary` or `--corpus-dir` only if you need to override a
recorded value.

While the campaign runs, watch these three numbers grow:

- `Total executions` — 2,000+ per second per worker is normal.
- `Crashes recorded` — increases when AFL++ finds new crashes.
- `Unique fingerprints` — the number of distinct underlying bugs.

## Reading a finding

```
Finding ID  Severity  Classification       Occurrences  Title
----------  --------  -------------------  -----------  -----------------------
ab12cd34    high      heap-buffer-overflow 6            heap-buffer-overflow in parse_chunk
```

- **Classification** is what the sanitizer reported. If KMCS is not certain,
  it says `unknown`. That is deliberate: KMCS does not guess.
- **Severity** is an evidence-based triage value. `high` means "this class
  of bug is generally significant"; it is not a claim that the bug is
  exploitable in any particular deployment.
- **Fingerprint** is a deterministic SHA-256 of the sanitizer evidence and
  the top of the stack trace. Two crashes with the same fingerprint are the
  same bug.
- **Occurrences** is how many crash artifacts collapsed into this finding.

## Reproducing a finding

```bash
kmcs finding show <finding-id>            # lists the linked crash IDs
kmcs crash show <crash-id>                # shows the preserved evidence
kmcs crash reproduce <crash-id> --target-binary /path/to/target_afl
```

`reproduce` replays the input three times by default and reports whether
every attempt crashed. The terminal outcomes are `REPRODUCED`,
`NOT_REPRODUCED`, and `INTERMITTENT`.

## Generating reports

```bash
kmcs report generate --format sarif   --output-dir ./reports
kmcs report generate --format markdown --output-dir ./reports
```

Five formats are available:

- **JSON** — stable schema, machine-readable, includes full evidence.
- **Markdown** — human-readable, for a ticket or an issue.
- **CSV** — for a spreadsheet.
- **SARIF 2.1.0** — for CI security dashboards.
- **HTML** — self-contained single file, printable to PDF.

## The TUI

For a live view of the workspace:

```bash
kmcs-tui
```

Press `1` through `8` to move between screens. Every list screen has a
detail pane on the right that shows the full record for the selected row.
Press `r` to refresh the current screen. Press `q` to quit.

## A checklist before you trust a campaign

1. Does the target crash by hand on a triggering input?
2. Does the target exit 0 on a benign input?
3. Does the target have AFL++ instrumentation (`nm target_afl | grep __afl_area_ptr`)?
4. Does the corpus contain only benign seeds?
5. Does ASan work on this machine (the probe in Trap 3)?

If any of these is "no", fix it before starting the campaign. Each of the
three traps above is one of these five questions.
