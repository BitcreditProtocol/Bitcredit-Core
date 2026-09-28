# Flutter FFI Setup

## Prerequisites

Make sure you have all [prerequisites](./prerequisites.md) installed.

* Install Rust
* Install Flutter
* Install [just](https://github.com/casey/just)
* `cargo install flutter_rust_bridge_codegen`

## Generate bindings

```bash
just flutter
```

## Import this package

This package can be imported as follows:

In `pubspec.yaml`:

```yaml
   ebill_flutter_ffi:
     git:
       url: git@github.com:BitcreditProtocol/Bitcredit-Core.git
       ref: vx.x.x
```

The `ref` can either be a commit hash, a branch or a tag.

### Precompiled binaries

This package publishes signed precompiled iOS and Android Rust binaries from
`.github/workflows/cd_precompiled.yml`. App CI can opt in by adding
`cargokit_options.yaml` at the Flutter app root:

```yaml
use_precompiled_binaries: true
```

Alternatively set `CARGOKIT_USE_PRECOMPILED_BINARIES=true` in the app build
environment. Cargokit falls back to a local Rust build if a signed binary for
the current crate hash and target is not available.

Then, in `main.dart`:

```dart
// there are api and data packages for all the different parts of the API
import 'package:ebill_flutter_ffi/ebill_flutter_ffi.dart';
import 'package:ebill_flutter_ffi/api/general.dart' as general;
import 'package:ebill_flutter_ffi/api/identity.dart' as identity;
import 'package:ebill_flutter_ffi/api/bill.dart' as bill;
import 'package:ebill_flutter_ffi/api/contact.dart' as contact;
import 'package:ebill_flutter_ffi/error.dart' as error;
import 'package:ebill_flutter_ffi/data/lib.dart' as data;
import 'package:ebill_flutter_ffi/data/identity.dart' as identity_data;
import 'package:ebill_flutter_ffi/data/contact.dart' as contact_data;
import 'package:ebill_flutter_ffi/data/bill.dart' as bill_data;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final conf = EbillConfig(
    dbFolderPath: dbDir,
    dbFolderPathFiles: dbDirFiles,
    logLevel: "debug",
    bitcoinNetwork: "testnet",
    esploraBaseUrls: ["https://esplora.minibill.tech"],
    nostrRelays: ["wss://relay.wildcat0.clowder-dev.minibill.tech"],
    blossomServers: ["https://relay.wildcat0.clowder-dev.minibill.tech"],
    nostrOnlyKnownContacts: false,
    jobRunnerInitialDelaySeconds: BigInt.from(5),
    jobRunnerCheckIntervalSeconds: BigInt.from(60),
    transportInitialSubscriptionDelaySeconds: 1,
    defaultMintUrl: "https://mint.wildcat0.clowder-dev.minibill.tech",
    defaultMintNodeId: "bitcrt020e50d48b6b2897743ca257c82684e984509c05c9bf812176c717005698e57023",
    numConfirmationsForPayment: BigInt.from(1),
    devMode: true,
    mandatoryEmailConfirmations: false,
    defaultCourtUrl: "https://bcr-court-dev.minibill.tech"
  );
  await RustLib.init();

  await initEbillFfi(conf: conf);

  try {
    final st = await general.getStatus();
    debugPrint('APP VERSION: ${st.appVersion}, ${st.bitcoinNetwork}, ${st.connected}');
  } on error.EbillFfiError catch (e) {
    debugPrint('Error, ${e.msg}, ${e.kind}');
  } catch (e, st) {
    debugPrint('Unexpected error: $e\n$st');
  }
  runApp(const MyApp());
}
```
