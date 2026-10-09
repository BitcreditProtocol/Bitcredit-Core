import 'package:ebill_ffi_harness/dev_config.dart';
import 'package:ebill_flutter_ffi/api/general.dart' as general_api;
import 'package:ebill_flutter_ffi/ebill_flutter_ffi.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets(
    'FRB initializes testnet instance and basic API calls work',
    (tester) async {
      await RustLib.init();

      final env = await DevEnvironment.prepare(
        spec: testnetSpec,
        suffix: 'integration',
        generateMnemonic: () async {
          final result =
              await general_api.generateRandomMnemonic();

          return result.mnemonic;
        },
      );

      await initEbillInstance(
        instanceId: InstanceId.testnet,
        conf: env.toConfig(),
      );

      await setActiveInstance(
        instanceId: InstanceId.testnet,
      );

      final activeInstance = await getActiveInstance();
      expect(
        activeInstance,
        InstanceId.testnet,
      );

      final status = await general_api.getStatus();

      expect(status.appVersion, isNotEmpty);
      expect(status.bitcoinNetwork, 'testnet');

      final currencies = await general_api.currencies();

      expect(currencies.currencies, isNotEmpty);
    },
  );
}
