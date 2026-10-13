import 'dart:io';
import 'package:ebill_flutter_ffi/ebill_flutter_ffi.dart';

class DevInstanceSpec {
  const DevInstanceSpec({
    required this.instanceId,
    required this.bitcoinNetwork,
    required this.esploraBaseUrls,
    required this.nostrRelays,
    required this.blossomServers,
    required this.defaultMintUrl,
    required this.defaultMintNodeId,
    required this.defaultCourtUrl,
  });

  final InstanceId instanceId;
  final String bitcoinNetwork;

  final List<String> esploraBaseUrls;
  final List<String> nostrRelays;
  final List<String> blossomServers;

  final String defaultMintUrl;
  final String defaultMintNodeId;
  final String defaultCourtUrl;
}


const testnetSpec = DevInstanceSpec(
  instanceId: InstanceId.testnet,
  bitcoinNetwork: 'testnet',
  esploraBaseUrls: [
    'https://esplora.minibill.tech',
  ],
  nostrRelays: [
    'wss://relay.wildcat0.clowder-dev.minibill.tech',
    'wss://relay.wildcat1.clowder-dev.minibill.tech',
  ],
  blossomServers: [
    'https://relay.wildcat0.clowder-dev.minibill.tech',
    'https://relay.wildcat1.clowder-dev.minibill.tech',
  ],
  defaultMintUrl:
      'https://mint.wildcat0.clowder-dev.minibill.tech',
  defaultMintNodeId:
      'bitcrt020e50d48b6b2897743ca257c82684e984509c05c9bf812176c717005698e57023',
  defaultCourtUrl:
      'https://bcr-court-dev.minibill.tech',
);

final mainnetSpec = DevInstanceSpec(
  instanceId: InstanceId.mainnet,
  bitcoinNetwork: 'mainnet',
  esploraBaseUrls: const [
    'https://esplora.minibill.tech',
  ],
  nostrRelays: const [
    'wss://relay.wildcat0.clowder-dev.minibill.tech',
    'wss://relay.wildcat1.clowder-dev.minibill.tech',
  ],
  blossomServers: const [
    'https://relay.wildcat0.clowder-dev.minibill.tech',
    'https://relay.wildcat1.clowder-dev.minibill.tech',
  ],
  defaultMintUrl:
      'https://mint.wildcat0.clowder-dev.minibill.tech',
  defaultMintNodeId:
      'bitcrm020e50d48b6b2897743ca257c82684e984509c05c9bf812176c717005698e57023',
  defaultCourtUrl:
      'https://bcr-court-dev.minibill.tech',
);

class DevEnvironment {
  DevEnvironment({
    required this.spec,
    required this.baseDir,
    required this.tempFilesDir,
    required this.sqliteDbFile,
    required this.mnemonicFile,
    required this.mnemonic,
  });

  final DevInstanceSpec spec;

  final Directory baseDir;
  final Directory tempFilesDir;
  final File sqliteDbFile;
  final File mnemonicFile;

  String mnemonic;

  InstanceId get instanceId => spec.instanceId;

  static Future<DevEnvironment> prepare({
    required DevInstanceSpec spec,
    String? suffix,
    required Future<String> Function() generateMnemonic,
  }) async {
    final override = Platform.environment['EBILL_HARNESS_DIR'];
    final defaultBase =
        '${Directory.systemTemp.path}/bitcredit-ebill-harness';
    final basePath = override ?? defaultBase;

    final suffixPart = suffix == null ? '' : '-$suffix';

    // per-instance:
    // /tmp/bitcredit-ebill-harness-testnet
    // /tmp/bitcredit-ebill-harness-mainnet
    final base = Directory(
      '$basePath$suffixPart-${spec.instanceId.name}',
    );

    final resetMarker = File('${base.path}.reset');

    if (await resetMarker.exists()) {
      if (await base.exists()) {
        await base.delete(recursive: true);
      }

      await resetMarker.delete();
    }

    final tempFiles = Directory('${base.path}/temp_files');
    final sqliteDir = Directory('${base.path}/sqlite');

    final sqliteDbFile = File('${sqliteDir.path}/ebill.db');
    final mnemonicFile = File('${base.path}/mnemonic.txt');

    await tempFiles.create(recursive: true);
    await sqliteDir.create(recursive: true);

    final String mnemonic;

    if (await mnemonicFile.exists()) {
      mnemonic = (await mnemonicFile.readAsString()).trim();

      if (mnemonic.isEmpty) {
        throw StateError(
          'Stored mnemonic is empty: ${mnemonicFile.path}',
        );
      }
    } else {
      mnemonic = (await generateMnemonic()).trim();

      await mnemonicFile.writeAsString(
        '$mnemonic\n',
        flush: true,
      );
    }

    return DevEnvironment(
      spec: spec,
      baseDir: base,
      tempFilesDir: tempFiles,
      sqliteDbFile: sqliteDbFile,
      mnemonicFile: mnemonicFile,
      mnemonic: mnemonic,
    );
  }

  Future<void> replaceMnemonic(String newMnemonic) async {
    final value = newMnemonic.trim();

    if (value.isEmpty) {
      throw ArgumentError('Mnemonic must not be empty');
    }

    await mnemonicFile.writeAsString(
      '$value\n',
      flush: true,
    );

    mnemonic = value;
  }

  static Future<void> requestReset(String basePath) async {
    final marker = File('$basePath.reset');

    await marker.create(recursive: true);
    await marker.writeAsString(
      'reset requested at '
      '${DateTime.now().toUtc().toIso8601String()}\n',
      flush: true,
    );
  }

  EbillConfig toConfig() => EbillConfig(
        sqliteDbPath: sqliteDbFile.path,
        tempFilesPath: tempFilesDir.path,
        logLevel: 'debug',
        bitcoinNetwork: spec.bitcoinNetwork,
        esploraBaseUrls: spec.esploraBaseUrls,
        nostrRelays: spec.nostrRelays,
        blossomServers: spec.blossomServers,
        nostrOnlyKnownContacts: false,
        jobRunnerInitialDelaySeconds: BigInt.from(5),
        jobRunnerCheckIntervalSeconds: BigInt.from(60),
        transportInitialSubscriptionDelaySeconds: 1,
        defaultMintUrl: spec.defaultMintUrl,
        defaultMintNodeId: spec.defaultMintNodeId,
        numConfirmationsForPayment: BigInt.one,
        devMode: true,
        mandatoryEmailConfirmations: false,
        defaultCourtUrl: spec.defaultCourtUrl,
        mnemonic: mnemonic,
      );
}

