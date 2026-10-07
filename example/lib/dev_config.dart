import 'dart:io';

import 'package:ebill_flutter_ffi/ebill_flutter_ffi.dart';

const defaultMintNodeId =
    'bitcrt020e50d48b6b2897743ca257c82684e984509c05c9bf812176c717005698e57023';
const defaultCourtUrl = 'https://bcr-court-dev.minibill.tech';
const defaultBlossomServer =
    'https://relay.wildcat0.clowder-dev.minibill.tech';

class DevEnvironment {
  DevEnvironment({
    required this.baseDir,
    required this.tempFilesDir,
    required this.sqliteDbFile,
    required this.mnemonicFile,
    required this.mnemonic,
  });

  final Directory baseDir;
  final Directory tempFilesDir;
  final File sqliteDbFile;
  final File mnemonicFile;

  String mnemonic;

  static Future<DevEnvironment> prepare({
    String? suffix,
    required Future<String> Function() generateMnemonic,
  }) async {
    final override = Platform.environment['EBILL_HARNESS_DIR'];
    final defaultBase =
        '${Directory.systemTemp.path}/bitcredit-ebill-harness';
    final basePath = override ?? defaultBase;

    final base = Directory(
      '$basePath${suffix == null ? '' : '-$suffix'}',
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
        bitcoinNetwork: 'testnet',
        esploraBaseUrls: const ['https://esplora.minibill.tech'],
        nostrRelays: const [
          'wss://relay.wildcat0.clowder-dev.minibill.tech',
          'wss://relay.wildcat1.clowder-dev.minibill.tech',
        ],
        blossomServers: const [
          'https://relay.wildcat0.clowder-dev.minibill.tech',
          'https://relay.wildcat1.clowder-dev.minibill.tech',
        ],
        nostrOnlyKnownContacts: false,
        jobRunnerInitialDelaySeconds: BigInt.from(5),
        jobRunnerCheckIntervalSeconds: BigInt.from(60),
        transportInitialSubscriptionDelaySeconds: 1,
        defaultMintUrl:
            'https://mint.wildcat0.clowder-dev.minibill.tech',
        defaultMintNodeId: defaultMintNodeId,
        numConfirmationsForPayment: BigInt.one,
        devMode: true,
        mandatoryEmailConfirmations: false,
        defaultCourtUrl: defaultCourtUrl,
        mnemonic: mnemonic,
      );
}
