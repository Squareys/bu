# CLAUDE.md

Notes for coding agents working on bu. The project's rules, build and test
commands, conventions and commit style are in
[CONTRIBUTING.md](CONTRIBUTING.md); they apply to agents exactly as to human
contributors. Read it first, then `docs/design.md` before changing behaviour
and `docs/format.md` before touching anything that reads or writes bytes on
disk.

- Treat the hard rules as binding. Do not work around one; ask when one
  seems to block a task.
- Say which test runs you did (plain, `--asan`, `--tsan`, `--smoke`) and
  their result when you report a change, and the size report when the
  binary moved.
- `scripts/test.sh --smoke` is the quick check while iterating; the full
  runs CONTRIBUTING.md asks for come before the commit.
