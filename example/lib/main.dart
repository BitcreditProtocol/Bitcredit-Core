import 'package:ebill_flutter_ffi/ebill_flutter_ffi.dart';
import 'package:flutter/material.dart';

import 'dev_config.dart';
import 'harness_page.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final env = await DevEnvironment.prepare();
  await RustLib.init();
  await initEbillFfi(conf: env.toConfig());

  runApp(EbillHarnessApp(dataDirectory: env.baseDir.path));
}

class EbillHarnessApp extends StatelessWidget {
  const EbillHarnessApp({required this.dataDirectory, super.key});

  final String dataDirectory;

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
      home: HarnessPage(dataDirectory: dataDirectory),
    );
  }
}
