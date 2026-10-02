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
    required this.dbDir,
    required this.tempFilesDir,
    required this.sqliteDbFile,
  });

  final Directory baseDir;
  final Directory dbDir;
  final Directory tempFilesDir;
  final File sqliteDbFile;

  static Future<DevEnvironment> prepare({String? suffix}) async {
    final override = Platform.environment['EBILL_HARNESS_DIR'];
    final defaultBase = '${Directory.systemTemp.path}/bitcredit-ebill-harness';
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

    final db = Directory('${base.path}/db');
    final files = Directory('${base.path}/files');
    final tempFiles = Directory('${base.path}/temp_files');
    final sqliteDir = Directory('${base.path}/sqlite');
    final sqliteDbFile = File('${sqliteDir.path}/ebill.db');

    await db.create(recursive: true);
    await files.create(recursive: true);
    await tempFiles.create(recursive: true);
    await sqliteDir.create(recursive: true);

    return DevEnvironment(baseDir: base, dbDir: db, tempFilesDir: tempFiles, sqliteDbFile: sqliteDbFile);
  }

  static Future<void> requestReset(String basePath) async {
    final marker = File('$basePath.reset');

    await marker.create(recursive: true);
    await marker.writeAsString(
        'reset requested at ${DateTime.now().toUtc().toIso8601String()}\n',
        flush: true,
        );
  }

  EbillConfig toConfig() => EbillConfig(
        dbFolderPath: dbDir.path,
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
        defaultMintUrl: 'https://mint.wildcat0.clowder-dev.minibill.tech',
        defaultMintNodeId: defaultMintNodeId,
        numConfirmationsForPayment: BigInt.one,
        devMode: true,
        mandatoryEmailConfirmations: false,
        defaultCourtUrl: defaultCourtUrl,
      );
}
