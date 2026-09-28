# E-Bill Flutter FFI test harness

Simple test harness for the E-Bill Flutter FFI

## Rebuild FFI Bindings

From the repository root:

```bash
just flutter
```

## Smoke test

```bash
flutter test integration_test/smoke_test.dart -d macos
# or
flutter test integration_test/smoke_test.dart -d linux
```

## Local state

By default the harness stores its DB/files under your platform temp directory in `bitcredit-ebill-harness/`. The exact path is shown at the top of the app.

To force a stable location, set `EBILL_HARNESS_DIR` before running, for example:

```bash
EBILL_HARNESS_DIR=/tmp/bitcredit-dev flutter run -d linux
```

Delete that directory to start with fresh local state. The integration smoke test appends `-integration` to the same base path.

