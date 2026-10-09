import 'package:ebill_ffi_harness/dev_config.dart';
import 'package:ebill_flutter_ffi/api/general.dart' as general_api;
import 'package:ebill_flutter_ffi/ebill_flutter_ffi.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:ebill_flutter_ffi/data/lib.dart' as data;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('FRB initializes and basic API calls work', (tester) async {
    await RustLib.init();
    final env = await DevEnvironment.prepare(
      suffix: 'integration',
      generateMnemonic: () async {
        final result = await general_api.generateRandomMnemonic();

        return result.mnemonic;
      },
    );
    await initEbillFfi(conf: env.toConfig());

    final status = await general_api.getStatus();
    expect(status.appVersion, isNotEmpty);

    final currencies = await general_api.currencies();
    expect(currencies.currencies, isNotEmpty);
  });
}
