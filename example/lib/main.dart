import 'package:ebill_flutter_ffi/ebill_flutter_ffi.dart';
import 'package:flutter/material.dart';
import 'package:ebill_flutter_ffi/api/general.dart' as general_api;

import 'dev_config.dart';
import 'harness_page.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();

  Future<String> generateMnemonic() async {
    final result =
      await general_api.generateRandomMnemonic();

    return result.mnemonic;
  }

  final testnet = await DevEnvironment.prepare(
    spec: testnetSpec,
    generateMnemonic: generateMnemonic,
  );

  final mainnet = await DevEnvironment.prepare(
    spec: mainnetSpec,
    generateMnemonic: generateMnemonic,
  );

  // per-instance
  // - Context
  // - jobs
  // - Nostr subscription
  await initEbillInstance(
    instanceId: InstanceId.testnet,
    conf: testnet.toConfig(),
  );

  await initEbillInstance(
    instanceId: InstanceId.mainnet,
    conf: mainnet.toConfig(),
  );

  // Always start with testnet
  await setActiveInstance(
    instanceId: InstanceId.testnet,
  );

  runApp(
    EbillHarnessApp(environments: {
        InstanceId.testnet: testnet,
        InstanceId.mainnet: mainnet,
    },
    initialInstance: InstanceId.testnet,
    ),
  );
}

class EbillHarnessApp extends StatelessWidget {
  const EbillHarnessApp({
    required this.environments,
    required this.initialInstance,
    super.key,
  });

  final Map<InstanceId, DevEnvironment> environments;
  final InstanceId initialInstance;

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
        environments: environments,
        initialInstance: initialInstance,
      ),
    );
  }
}
