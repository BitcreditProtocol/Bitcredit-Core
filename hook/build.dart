// Build hook: compiles crates/bcr-ebill-flutter-ffi into the code asset the
// generated bindings load, or downloads its signed precompiled binary. Flutter
// runs it for every platform build; see docs/flutter.md "Precompiled binaries".

import 'dart:io';

import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';

import 'src/precompiled_binaries.dart';

// Repository-specific values; everything else is in src/.
const cratePath = 'crates/bcr-ebill-flutter-ffi';
const libraryName = 'bcr_ebill_flutter_ffi';
const assetName = 'src/rust/frb_generated.io.dart';

const rustLibrary = RustLibraryBuilder(
  cratePath: cratePath,
  libraryName: libraryName,
  assetName: assetName,
);

void main(List<String> args) async {
  await build(args, (input, output) async {
    final logger = Logger.detached('$libraryName hook')
      ..level = Level.INFO
      ..onRecord.listen(stdout.writeln);
    await rustLibrary.run(input: input, output: output, logger: logger);
  });
}
