import 'package:ebill_flutter_ffi/ebill_flutter_ffi.dart';
import 'package:flutter/material.dart';
import 'package:ebill_flutter_ffi/data/lib.dart' as data;
import 'package:ebill_flutter_ffi/api/general.dart' as general_api;

import 'dev_config.dart';
import 'harness_page.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();

  final env = await DevEnvironment.prepare(
    generateMnemonic: () async {
      final result = await general_api.generateRandomMnemonic();

      return result.mnemonic;
    },
  );

  await initEbillFfi(
    conf: env.toConfig(),
  );

  runApp(
    EbillHarnessApp(environment: env),
  );
}

class EbillHarnessApp extends StatelessWidget {
  const EbillHarnessApp({
    required this.environment,
    super.key,
  });

  final DevEnvironment environment;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Bitcredit E-Bill FFI Test Harness',
      theme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        brightness: Brightness.light,
        useMaterial3: true,
      ),
      home: HarnessPage(
        environment: environment,
      ),
    );
  }
}
