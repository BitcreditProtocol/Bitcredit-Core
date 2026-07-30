/// This is copied from Cargokit (which is the official way to use it currently)
/// Details: https://fzyzcjy.github.io/flutter_rust_bridge/manual/integrate/builtin

import 'dart:convert';
import 'dart:io';

import 'package:ed25519_edwards/ed25519_edwards.dart';
import 'package:github/github.dart';
import 'package:logging/logging.dart';
import 'package:path/path.dart' as path;

import 'artifacts_provider.dart';
import 'builder.dart';
import 'cargo.dart';
import 'crate_hash.dart';
import 'options.dart';
import 'rustup.dart';
import 'target.dart';

final _log = Logger('precompile_binaries');

class PrecompileBinaries {
  PrecompileBinaries({
    required this.privateKey,
    required this.githubToken,
    required this.repositorySlug,
    required this.manifestDir,
    required this.targets,
    this.targetCommitish,
    required this.prerelease,
    this.androidSdkLocation,
    this.androidNdkVersion,
    this.androidMinSdkVersion,
    this.tempDir,
  });

  final PrivateKey privateKey;
  final String githubToken;
  final RepositorySlug repositorySlug;
  final String manifestDir;
  final List<Target> targets;
  final String? targetCommitish;
  final bool prerelease;
  final String? androidSdkLocation;
  final String? androidNdkVersion;
  final int? androidMinSdkVersion;
  final String? tempDir;

  static String fileName(Target target, String name) {
    return '${target.rust}_$name';
  }

  static String signatureFileName(Target target, String name) {
    return '${target.rust}_$name.sig';
  }

  Future<void> run() async {
    final crateInfo = CrateInfo.load(manifestDir);

    final targets = List.of(this.targets);
    if (targets.isEmpty) {
      targets.addAll([
        ...Target.buildableTargets(),
        if (androidSdkLocation != null) ...Target.androidTargets(),
      ]);
    }

    _log.info('Precompiling binaries for $targets');

    final hash = CrateHash.compute(manifestDir);
    _log.info('Computed crate hash: $hash');

    final String tagName = 'precompiled_$hash';

    final github = GitHub(auth: Authentication.withToken(githubToken));
    final repo = github.repositories;
    var release = await _getOrCreateRelease(
      repo: repo,
      tagName: tagName,
      packageName: crateInfo.packageName,
      hash: hash,
      github: github,
    );

    final tempDir = this.tempDir != null
        ? Directory(this.tempDir!)
        : Directory.systemTemp.createTempSync('precompiled_');

    tempDir.createSync(recursive: true);

    final crateOptions = CargokitCrateOptions.load(
      manifestDir: manifestDir,
    );

    final buildEnvironment = BuildEnvironment(
      configuration: BuildConfiguration.release,
      crateOptions: crateOptions,
      targetTempDir: tempDir.path,
      manifestDir: manifestDir,
      crateInfo: crateInfo,
      isAndroid: androidSdkLocation != null,
      androidSdkPath: androidSdkLocation,
      androidNdkVersion: androidNdkVersion,
      androidMinSdkVersion: androidMinSdkVersion,
    );

    final rustup = Rustup();
    final releaseAssets = await _releaseAssetsByName(repo, release);

    for (final target in targets) {
      final artifactNames = getArtifactNames(
        target: target,
        libraryName: crateInfo.packageName,
        remote: true,
      );
      final requiredAssetNames = artifactNames
          .expand((name) => [
                PrecompileBinaries.fileName(target, name),
                signatureFileName(target, name),
              ])
          .toList(growable: false);

      final uploadedRequiredAssetNames = requiredAssetNames
          .where((name) => _assetIsUploaded(releaseAssets[name]))
          .toList(growable: false);

      if (uploadedRequiredAssetNames.length == requiredAssetNames.length) {
        _log.info('All artifacts for $target already exist - skipping');
        continue;
      }

      final existingRequiredAssetNames = requiredAssetNames
          .where((name) => releaseAssets.containsKey(name))
          .toList(growable: false);
      if (existingRequiredAssetNames.isNotEmpty) {
        _log.warning(
            'Found partial artifacts for $target - deleting and rebuilding: '
            '$existingRequiredAssetNames');
        for (final name in existingRequiredAssetNames) {
          final asset = releaseAssets.remove(name)!;
          await repo.deleteReleaseAsset(repositorySlug, asset);
        }
      }

      _log.info('Building for $target');

      final builder =
          RustBuilder(target: target, environment: buildEnvironment);
      builder.prepare(rustup);
      final res = await builder.build();

      final assets = <CreateReleaseAsset>[];
      for (final name in artifactNames) {
        final file = File(path.join(res, name));
        if (!file.existsSync()) {
          throw Exception('Missing artifact: ${file.path}');
        }

        final data = file.readAsBytesSync();
        final create = CreateReleaseAsset(
          name: PrecompileBinaries.fileName(target, name),
          contentType: "application/octet-stream",
          assetData: data,
        );
        final signature = sign(privateKey, data);
        final signatureCreate = CreateReleaseAsset(
          name: signatureFileName(target, name),
          contentType: "application/octet-stream",
          assetData: signature,
        );
        bool verified = verify(public(privateKey), data, signature);
        if (!verified) {
          throw Exception('Signature verification failed');
        }
        assets.add(create);
        assets.add(signatureCreate);
      }
      _log.info('Uploading assets: ${assets.map((e) => e.name)}');
      for (final asset in assets) {
        // This seems to be failing on CI so do it one by one
        int retryCount = 0;
        while (true) {
          try {
            final uploaded = await repo.uploadReleaseAssets(release, [asset]);
            for (final uploadedAsset in uploaded) {
              final name = uploadedAsset.name;
              if (name != null) {
                releaseAssets[name] = uploadedAsset;
              }
            }
            break;
          } on Exception catch (e) {
            if (retryCount == 10) {
              rethrow;
            }
            ++retryCount;
            _log.shout(
                'Upload failed (attempt $retryCount, will retry): ${e.toString()}');
            await Future.delayed(Duration(seconds: 2));
          }
        }
      }

      final missingAssetNames = requiredAssetNames
          .where((name) => !_assetIsUploaded(releaseAssets[name]))
          .toList(growable: false);
      if (missingAssetNames.isNotEmpty) {
        throw Exception('Missing uploaded assets for $target: '
            '${missingAssetNames.join(', ')}');
      }
    }

    _log.info('Cleaning up');
    tempDir.deleteSync(recursive: true);
  }

  Future<Map<String, ReleaseAsset>> _releaseAssetsByName(
    RepositoriesService repo,
    Release release,
  ) async {
    if (release.id == null) {
      return {};
    }
    final assets =
        await repo.listReleaseAssets(repositorySlug, release).toList();
    return {
      for (final asset in assets)
        if (asset.name != null) asset.name!: asset,
    };
  }

  bool _assetIsUploaded(ReleaseAsset? asset) {
    return asset?.state == 'uploaded';
  }

  Future<Release> _getOrCreateRelease({
    required RepositoriesService repo,
    required String tagName,
    required String packageName,
    required String hash,
    required GitHub github,
  }) async {
    Release release;
    try {
      _log.info('Fetching release $tagName');
      release = await repo.getReleaseByTagName(repositorySlug, tagName);
    } on ReleaseNotFound {
      _log.info('Release not found - creating release $tagName');
      release = await github.postJSON<Map<String, dynamic>, Release>(
        '/repos/${repositorySlug.fullName}/releases',
        statusCode: 201,
        convert: Release.fromJson,
        body: jsonEncode({
          'tag_name': tagName,
          'name': 'Precompiled binaries ${hash.substring(0, 8)}',
          if (targetCommitish != null) 'target_commitish': targetCommitish,
          'draft': false,
          'prerelease': prerelease,
          'make_latest': 'false',
          'body': 'Precompiled binaries for crate $packageName, '
              'crate hash $hash.',
        }),
      );
    }
    return _updateReleaseMetadata(github, release);
  }

  Future<Release> _updateReleaseMetadata(
    GitHub github,
    Release release,
  ) async {
    final releaseId = release.id;
    if (releaseId == null) {
      return release;
    }
    return github.patchJSON<Map<String, dynamic>, Release>(
      '/repos/${repositorySlug.fullName}/releases/$releaseId',
      statusCode: 200,
      convert: Release.fromJson,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'prerelease': prerelease,
        'make_latest': 'false',
      }),
    );
  }
}
