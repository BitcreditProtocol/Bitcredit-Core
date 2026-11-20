// Builds, signs and uploads the precompiled binaries hook/build.dart
// downloads. Run by .github/workflows/cd_precompiled.yml from the package
// root; replaces cargokit's `build_tool precompile-binaries`.
//
//   cd tool && dart pub get
//   PRIVATE_KEY=<hex> GITHUB_TOKEN=<token> dart run precompile_binaries.dart \
//     --repository=<owner>/<repo> --target=aarch64-linux-android ...
//
// tool/ is its own package because `dart run` of a script first runs the
// build hooks of the script's package graph: run from the root package, it
// builds the Rust library for the host through hook/build.dart (measured,
// over 2 minutes). Running a dependency's executable, such as
// `dart run build_runner` in an app, runs no hooks.
//
// Each target is built by the hook's own builder on a synthesized hook input,
// so a precompiled binary gets the same cargo environment (Android NDK linker
// and 16 KB pages, Apple deployment targets) as an app's local build.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:code_assets/code_assets.dart';
import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:github/github.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:path/path.dart' as path;
import 'package:yaml/yaml.dart';

import '../hook/build.dart' show cratePath, libraryName, rustLibrary;
import '../hook/src/precompiled_binaries.dart';

final _log = Logger('precompile_binaries');

Future<void> main(List<String> args) async {
  final parser = ArgParser()
    ..addOption('repository', mandatory: true, help: 'owner/name')
    ..addOption('target-commitish', help: 'Commit the release tag points at')
    ..addFlag('prerelease', help: 'Mark a newly created release a prerelease')
    ..addMultiOption('target', help: 'Rust target triple to build')
    ..addOption(
      'android-ndk',
      help: 'NDK directory; required for Android targets',
    )
    ..addOption(
      'package-root',
      defaultsTo: '..',
      help: 'The ebill_flutter_ffi package root',
    )
    ..addFlag('print-hash', help: 'Only print the crate hash and exit');
  final options = parser.parse(args);

  Logger.root
    ..level = Level.INFO
    ..onRecord.listen(stdout.writeln);

  final packageRoot = path.normalize(
    path.absolute(options.option('package-root')!),
  );
  final crateHash = CrateHash(
    packageRoot: packageRoot,
    manifestDir: path.join(packageRoot, cratePath),
  ).compute();
  if (options.flag('print-hash')) {
    stdout.writeln(crateHash);
    return;
  }

  // Resolve every target first, so a bad --target or a missing
  // --android-ndk fails before a release is created or anything uploaded.
  final targetNames = options.multiOption('target');
  if (targetNames.isEmpty) {
    throw ArgumentError('Pass at least one --target');
  }
  final ndk = options.option('android-ndk');
  final targets = [
    for (final triple in targetNames)
      (triple, _codeConfigFor(triple, ndk: ndk)),
  ];

  final privateKeyBytes = hex.decode(_requireEnv('PRIVATE_KEY'));
  if (privateKeyBytes.length != 64) {
    throw ArgumentError('PRIVATE_KEY must be 64 bytes hex');
  }
  final privateKey = ed.PrivateKey(privateKeyBytes);
  final config = PrecompiledBinariesConfig.load(packageRoot);
  if (!const ListEquality<int>().equals(
    ed.public(privateKey).bytes,
    config.publicKey.bytes,
  )) {
    throw ArgumentError(
      'PRIVATE_KEY does not match public_key in '
      '${PrecompiledBinariesConfig.fileName}',
    );
  }

  final slug = RepositorySlug.full(options.option('repository')!);
  final github = GitHub(
    auth: Authentication.withToken(_requireEnv('GITHUB_TOKEN')),
  );
  final releases = _Releases(github, slug);

  final tagName = 'precompiled_$crateHash';
  _log.info('Crate hash $crateHash, release $tagName');
  final release = await releases.getOrCreate(
    tagName: tagName,
    crateHash: crateHash,
    targetCommitish: options.option('target-commitish'),
    prerelease: options.flag('prerelease'),
  );
  final assets = await releases.assetsByName(release);
  final tempDir = Directory.systemTemp.createTempSync('precompiled_');

  try {
    for (final (triple, code) in targets) {
      final libraryFile = code.targetOS.dylibFileName(libraryName);
      final names = [
        remoteFileName(triple, libraryFile),
        signatureFileName(triple, libraryFile),
      ];
      if (names.every((name) => assets[name]?.state == 'uploaded')) {
        _log.info('$triple already uploaded, skipping');
        continue;
      }
      for (final name in names.where(assets.containsKey)) {
        _log.warning('Deleting partial asset $name before rebuilding');
        await github.repositories.deleteReleaseAsset(
          slug,
          assets.remove(name)!,
        );
      }

      _log.info('Building $triple');
      final library = await _build(code, packageRoot, tempDir);
      // The build runs with --locked, but a build script could still write
      // into a crate: never sign a binary under a hash it does not match.
      final hashAfterBuild = CrateHash(
        packageRoot: packageRoot,
        manifestDir: path.join(packageRoot, cratePath),
      ).compute();
      if (hashAfterBuild != crateHash) {
        throw StateError(
          'Building $triple changed the crate hash from $crateHash to '
          '$hashAfterBuild; refusing to publish it under $tagName',
        );
      }
      if (code.targetOS == OS.android &&
          code.targetArchitecture != Architecture.arm) {
        checkAndroidPageAlignment(library);
      }
      final data = library.readAsBytesSync();
      final signature = ed.sign(privateKey, data);
      if (!ed.verify(config.publicKey, data, signature)) {
        throw StateError('Signature verification failed for $triple');
      }

      for (final (name, bytes) in [(names[0], data), (names[1], signature)]) {
        final uploaded = await releases.upload(release, name, bytes);
        assets[name] = uploaded;
      }
      final notUploaded = names.where(
        (name) => assets[name]?.state != 'uploaded',
      );
      if (notUploaded.isNotEmpty) {
        throw StateError(
          'Assets for $triple not in state "uploaded": '
          '${notUploaded.join(', ')}',
        );
      }
    }
  } finally {
    tempDir.deleteSync(recursive: true);
    github.dispose();
  }
}

String _requireEnv(String name) {
  final value = Platform.environment[name];
  if (value == null || value.isEmpty) {
    throw ArgumentError('Missing $name environment variable');
  }
  return value;
}

/// The hook input config Flutter would pass for [triple] at the
/// `precompiled*` minimum platform versions.
CodeAssetExtension _codeConfigFor(String triple, {String? ndk}) {
  final (os, arch) = switch (triple) {
    'armv7-linux-androideabi' => (OS.android, Architecture.arm),
    'aarch64-linux-android' => (OS.android, Architecture.arm64),
    'x86_64-linux-android' => (OS.android, Architecture.x64),
    'aarch64-apple-ios' ||
    'aarch64-apple-ios-sim' => (OS.iOS, Architecture.arm64),
    'x86_64-apple-ios' => (OS.iOS, Architecture.x64),
    'aarch64-apple-darwin' => (OS.macOS, Architecture.arm64),
    'x86_64-apple-darwin' => (OS.macOS, Architecture.x64),
    'aarch64-unknown-linux-gnu' => (OS.linux, Architecture.arm64),
    'x86_64-unknown-linux-gnu' => (OS.linux, Architecture.x64),
    'aarch64-pc-windows-msvc' => (OS.windows, Architecture.arm64),
    'x86_64-pc-windows-msvc' => (OS.windows, Architecture.x64),
    _ => throw ArgumentError('No precompiled binaries for target $triple'),
  };
  final iOSSdk = triple == 'aarch64-apple-ios'
      ? IOSSdk.iPhoneOS
      : IOSSdk.iPhoneSimulator;
  return CodeAssetExtension(
    targetOS: os,
    targetArchitecture: arch,
    linkModePreference: LinkModePreference.dynamic,
    cCompiler: os == OS.android ? _ndkCompiler(ndk) : null,
    android: os == OS.android
        ? AndroidCodeConfig(targetNdkApi: precompiledAndroidNdkApi)
        : null,
    iOS: os == OS.iOS
        ? IOSCodeConfig(
            targetSdk: iOSSdk,
            deploymentVersion: AppleVersion(precompiledIOSVersion),
          )
        : null,
    macOS: os == OS.macOS
        ? MacOSCodeConfig(
            deploymentVersion: AppleVersion(precompiledMacOSVersion),
          )
        : null,
  );
}

/// The NDK clang toolchain, as flutter_tools passes it to build hooks.
CCompilerConfig _ndkCompiler(String? ndk) {
  if (ndk == null) {
    throw ArgumentError('Android targets need --android-ndk');
  }
  final host = Platform.isMacOS ? 'darwin-x86_64' : 'linux-x86_64';
  final bin = path.join(ndk, 'toolchains', 'llvm', 'prebuilt', host, 'bin');
  final [compiler, linker, archiver] = [
    for (final tool in ['clang', 'ld.lld', 'llvm-ar']) path.join(bin, tool),
  ];
  // Fail in the preflight, before credentials and the release are touched.
  for (final file in [compiler, linker, archiver]) {
    if (!File(file).existsSync()) {
      throw ArgumentError('--android-ndk: $file does not exist');
    }
  }
  return CCompilerConfig(
    compiler: Uri.file(compiler),
    linker: Uri.file(linker),
    archiver: Uri.file(archiver),
  );
}

/// Runs the hook's builder for one target with a local cargo build and
/// returns the library file it produced.
Future<File> _build(
  CodeAssetExtension extension,
  String packageRoot,
  Directory tempDir,
) async {
  final shared = Directory(path.join(tempDir.path, 'shared'))
    ..createSync(recursive: true);
  final inputBuilder = BuildInputBuilder()
    ..setupShared(
      packageRoot: Directory(packageRoot).uri,
      packageName: _packageName(packageRoot),
      outputDirectoryShared: shared.uri,
      outputFile: tempDir.uri.resolve('output.json'),
    )
    ..setupBuildInput()
    ..config.setupBuild(linkingEnabled: false);
  extension
    ..setupLogger(_log)
    ..setupBuildInput(inputBuilder);
  final input = inputBuilder.build();
  final errors = await extension.validateBuildInput(input);
  if (errors.isNotEmpty) {
    throw StateError('Invalid build input: $errors');
  }

  final output = BuildOutputBuilder();
  await rustLibrary.run(
    input: input,
    output: output,
    logger: _log,
    usePrecompiled: false,
    locked: true,
  );
  final built = output.build();
  // The same output checks flutter_tools runs (file type, architecture).
  final outputErrors = await extension.validateBuildOutput(input, built);
  if (outputErrors.isNotEmpty) {
    throw StateError('Invalid build output: $outputErrors');
  }
  final code = built.assets.code;
  if (code.length != 1) {
    throw StateError('Expected one code asset, got ${code.length}');
  }
  return File.fromUri(code.single.file!);
}

String _packageName(String packageRoot) {
  final pubspec = File(path.join(packageRoot, 'pubspec.yaml'));
  return (loadYaml(pubspec.readAsStringSync()) as YamlMap)['name'] as String;
}

/// GitHub release access, ported from cargokit's precompile_binaries.dart
/// (including its local overrides: a release made by a concurrent job is
/// reused, and is never marked latest).
class _Releases {
  _Releases(this.github, this.slug);

  final GitHub github;
  final RepositorySlug slug;

  Future<Release> getOrCreate({
    required String tagName,
    required String crateHash,
    required String? targetCommitish,
    required bool prerelease,
  }) async {
    Release release;
    try {
      release = await github.repositories.getReleaseByTagName(slug, tagName);
    } on ReleaseNotFound {
      _log.info('Creating release $tagName');
      try {
        release = await github.postJSON<Map<String, dynamic>, Release>(
          '/repos/${slug.fullName}/releases',
          statusCode: 201,
          convert: Release.fromJson,
          body: jsonEncode({
            'tag_name': tagName,
            'name': 'Precompiled binaries ${crateHash.substring(0, 8)}',
            'target_commitish': ?targetCommitish,
            'draft': false,
            'prerelease': prerelease,
            'make_latest': 'false',
            'body':
                'Precompiled binaries for crate $libraryName, '
                'crate hash $crateHash.',
          }),
        );
      } on ValidationFailed {
        // A concurrent job created the tag first (HTTP 422); reuse it.
        release = await _fetchWithRetry(tagName);
      }
    }
    return github.patchJSON<Map<String, dynamic>, Release>(
      '/repos/${slug.fullName}/releases/${release.id}',
      statusCode: 200,
      convert: Release.fromJson,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'prerelease': prerelease, 'make_latest': 'false'}),
    );
  }

  Future<Release> _fetchWithRetry(String tagName) async {
    for (var attempt = 1; ; attempt++) {
      try {
        return await github.repositories.getReleaseByTagName(slug, tagName);
      } on ReleaseNotFound {
        if (attempt == 5) {
          rethrow;
        }
        await Future<void>.delayed(const Duration(seconds: 2));
      }
    }
  }

  Future<Map<String, ReleaseAsset>> assetsByName(Release release) async {
    final assets = await github.repositories
        .listReleaseAssets(slug, release)
        .toList();
    return {
      for (final asset in assets)
        if (asset.name != null) asset.name!: asset,
    };
  }

  Future<ReleaseAsset> upload(
    Release release,
    String name,
    Uint8List data,
  ) async {
    for (var attempt = 1; ; attempt++) {
      try {
        final uploaded = await github.repositories.uploadReleaseAssets(
          release,
          [
            CreateReleaseAsset(
              name: name,
              contentType: 'application/octet-stream',
              assetData: data,
            ),
          ],
        );
        _log.info('Uploaded $name');
        return uploaded.single;
      } on Exception catch (e) {
        if (attempt == 10) {
          rethrow;
        }
        _log.warning('Upload of $name failed (attempt $attempt): $e');
        await Future<void>.delayed(const Duration(seconds: 2));
      }
    }
  }
}
