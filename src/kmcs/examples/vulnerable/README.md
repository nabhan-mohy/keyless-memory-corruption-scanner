# KMCS demonstration laboratory

Nine intentionally vulnerable C programs. Each is a *deliberate* bug used to
test that KMCS detects the crash it is supposed to detect. **Do not deploy
any of these programs.** They exist so that KMCS can verify itself against
programs whose expected outcome is known in advance.

| File | Bug class | Sanitizer | Trigger |
| --- | --- | --- | --- |
| `heap_overflow.c` | heap-buffer-overflow | ASan | Any input longer than 8 bytes |
| `stack_overflow.c` | stack-buffer-overflow | ASan | Any input longer than 8 bytes |
| `global_overflow.c` | global-buffer-overflow | ASan | Any input longer than 8 bytes |
| `use_after_free.c` | heap-use-after-free | ASan | Any non-empty input |
| `double_free.c` | double-free | ASan | Any input |
| `null_deref.c` | SEGV / null-pointer-dereference | ASan | Any input |
| `oob_read.c` | heap-buffer-overflow (read) | ASan | A digit `'4'`..`'9'` |
| `signed_overflow.c` | undefined behaviour | UBSan | Any byte > 0 |
| `memory_leak.c` | memory leak | LSan | Any input |

Each program reads from `stdin` and exits.  Fuzzing is trivial: feed any
non-empty input.
