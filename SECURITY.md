# Security policy

## Supported versions

Only the latest release gets security fixes. bu has not reached 1.0, so a
fix may come with a format change; the release notes say so when it does.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub: on
<https://github.com/Squareys/bu>, open the **Security** tab and choose
**Report a vulnerability**.

Include:

- the bu version (`bu --version`) and how you built or obtained it;
- what an attacker can do, and what they need to have first (the key file, a
  passphrase, write access to a chain, a crafted file to back up, ...);
- steps or a small script that reproduce it, with the command lines you ran;
- for a malformed chain, key or index file, the smallest file that shows it
  (made with `--no-key` or a throwaway key, never with a real one).

## What to expect

You will get an acknowledgement within a week. Once the maintainer confirms
the issue, the fix goes into a private advisory and a new release, and then
the advisory goes public with credit to you, unless you ask to stay
unnamed.

The threat model ([docs/design.md §11](docs/design.md#11-threat-model)) says
what bu protects against and what it leaves out. Reports that challenge it
are welcome too.
