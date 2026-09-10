# Unit tests

Host-side tests for functions the ragger suite cannot reach.

`tests/` drives the app over APDUs, so it only sees what leaves the device: a
response or a screen. That is right for anything about APDU order, device state
or what the user is shown. It cannot reach a function that no command can call
with bad arguments — which is most of the bounds bugs in the Cerberus scan.

These tests call the functions directly.

## Run

These build with the host compiler for x86-64 and run natively. No device, no
Speculos, no cross-compiler, no container.

```
export BOLOS_SDK=/path/to/ledger-secure-sdk
cmake -B build -S .
cmake --build build
ctest --test-dir build --output-on-failure
```

`ctest` counts one test per executable — `add_test(NAME ${ARG_NAME} ...)` in
`LedgerUT.cmake` — so `0 tests failed out of 1` means one *suite*, not one test,
and `--output-on-failure` prints nothing while everything passes.

To see the tests inside:

```
ctest --test-dir build -V          # every Unity line, prefixed with the suite
./build/test_monero_base58         # the same, run directly
ctest --test-dir build -N          # what ctest knows: one entry per suite
```

One Unity failure therefore reports as `1/1 failed`, with the offending test
named only because `--output-on-failure` dumps the binary's output. Keep that
flag for CI; use `-V` to see the roster.

Coverage: `cmake --build build --target generate_coverage`.

Needs `cmake` >= 3.28, `ruby` (CMock generates mocks with it), a host C
compiler, and `gcovr` for coverage. `BOLOS_SDK` only has to point at an SDK
checkout — the headers and `cmake/LedgerUT.cmake` are read from it; nothing is
built for the device.

If the host is missing cmake or ruby, the dev-tools image has both:

```
docker run --rm -v "$PWD/..:/app" -v /path/to/ledger-secure-sdk:/tmp/my-sdk \
  -e BOLOS_SDK=/tmp/my-sdk -w /app/unit-tests \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
  bash -c 'cmake -B build -S . && cmake --build build && ctest --test-dir build --output-on-failure'
```

Use a separate build directory for each, since the two toolchains produce
different objects.

## Layout

    CMakeLists.txt          one ledger_unit_tests_add_test() per suite
    stubs/                  what the app needs but the tests do not
    test_monero_base58.c    monero_base58_public_key
    test_monero_crypto.c    the hash, modular-arithmetic and amount helpers
    test_monero_blind.c     monero_unblind
    test_monero_io.c        monero_io_do, monero_io_hole, the key fetchers

The framework is `LedgerUT` from the SDK: Unity for assertions, CMock available
for SDK syscalls. `app-boilerplate/unit-tests/` is the reference.

## Known bugs

A test must never *pass* because a bug is present. Write what the code should
do, and mark it `TEST_IGNORE_MESSAGE(...)` with the ticket reference until it
holds. Unity counts ignores separately and prints the reason, so it stays
visible, and fixing the bug means deleting one line rather than rewriting the
test.

Keep any reproducer as its own test, also ignored, so the bug stays
demonstrable without reporting green.

Note this is xfail: an ignored test does not fail the build.

## Adding a suite

Add a `ledger_unit_tests_add_test()` block naming the source under test, and a
`test_<name>.c` beside it. Add what that source needs from elsewhere to
`stubs/`.

`test_monero_base58` needs no `MOCK_HEADERS`: hand-written stubs cover it. Add
them when a suite calls an SDK function it has to control — CMock then replaces
every function in the listed header, so never list one declaring the function
under test. `app-boilerplate/unit-tests/` has examples.

Four things cost time the first go:

**Include order.** `monero_api.h` and `monero_vars.h` include each other, and
the static inlines in `monero_api.h` use `G_monero_vstate`, which
`monero_vars.h` declares. So reach `monero_api.h` first; start from
`monero_vars.h` and the guards unwind wrong. `cx.h` has to precede
`monero_types.h`, which uses `cx_sha3_t`.

**Stub what the wrapper calls, not the wrapper.** `monero_keccak_F` is a static
inline, so it cannot be replaced. `monero_hash` underneath it can.

**`N_state_pic` is const**, because on device it is NVRAM. A const object lands
in `.rodata`, so a test that writes it segfaults. `stubs/stub_monero.c` aliases
the symbol onto writable storage.

**`send_error_and_kill_app` is `noreturn`**, so a stub cannot just record the
status and return. `stubs/stub_io.c` longjmps to a `jmp_buf` the test sets, and
the test reads the status from `stub_kill_sw`. Unity's own `TEST_PROTECT` is
the wrong tool: it lands in Unity's abort frame and counts as a failure, when
being killed is the behaviour under test.

## The `app` target

`ledger_unit_tests_build_app_sources_as_lib()` builds an `app` library from
every source except the UI ones, so coverage has a denominator. Nothing links
it, but it still has to compile — which is why the app's `DEFINES` from the
Makefile are in `UT_COMPILE_DEFS`, even though no test needs them.

So `cmake --build build` can fail on a file no test touches. Build one suite
(`--build build --target test_<name>`) while working, and the default target
before pushing.

`monero_ux_*.c` are filtered out. They only draw, which the ragger snapshots
check and a unit test cannot, and compiling them would mean declaring every
generated icon here for no gain. Coverage is over the code these tests can
reach.

`stubs/glyphs.h` is empty but required: the SDK's `ux_nbgl.h` includes it and
every source reaches that through `os.h`, so even a test touching no UI needs
the file to exist.
