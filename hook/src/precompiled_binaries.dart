// Builds the Rust FFI library as a Dart/Flutter code asset, preferring a
// signed precompiled binary over a local cargo build.
//
// Replaces cargokit's build_tool (artifacts_provider, crate_hash, options) and
// is shared by hook/build.dart (app builds) and tool/precompile_binaries.dart
// (CI release builds), so both produce a binary the same way.
//
// Nothing in this file is specific to one repository; hook/build.dart passes
// the crate path and library name.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:code_assets/code_assets.dart';
import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_rust_bridge_hooks/flutter_rust_bridge_hooks.dart';
import 'package:http/http.dart' as http;
import 'package:logging/logging.dart';
import 'package:path/path.dart' as path;
import 'package:toml/toml.dart';
import 'package:yaml/yaml.dart';

/// Minimum platform versions the precompiled binaries are built for.
///
/// They match the minimums flutter_tools passes to build hooks (Flutter's
/// default `minSdk`, `targetIOSVersion` and `targetMacOSVersion`). A build
/// asking for an older platform falls back to a local cargo build. They are
/// part of the crate hash, so changing one publishes new binaries.
const precompiledAndroidNdkApi = 24;
const precompiledIOSVersion = 15;
const precompiledMacOSVersion = 13;

/// Android targets whose libraries must be linked for 16 KB pages.
const _pageSizeTargets = {'aarch64-linux-android', 'x86_64-linux-android'};
const _pageSize = 16384;

/// The `<package root>/precompiled_binaries.yaml` settings.
class PrecompiledBinariesConfig {
  PrecompiledBinariesConfig({required this.urlPrefix, required this.publicKey});

  static const fileName = 'precompiled_binaries.yaml';

  /// Release download URL up to the crate hash, e.g.
  /// `https://github.com/<org>/<repo>/releases/download/precompiled_`.
  final String urlPrefix;

  /// Ed25519 public key that verifies the `.sig` of every downloaded binary.
  final ed.PublicKey publicKey;

  static PrecompiledBinariesConfig load(String packageRoot) {
    final file = File(path.join(packageRoot, fileName));
    final yaml = loadYaml(file.readAsStringSync(), sourceUrl: file.uri);
    if (yaml is! YamlMap ||
        yaml['url_prefix'] is! String ||
        yaml['public_key'] is! String) {
      throw FormatException(
        '${file.path} must set url_prefix and public_key strings',
      );
    }
    final key = hex.decode(yaml['public_key'] as String);
    if (key.length != 32) {
      throw FormatException('${file.path}: public_key must be 32 bytes hex');
    }
    return PrecompiledBinariesConfig(
      urlPrefix: yaml['url_prefix'] as String,
      publicKey: ed.PublicKey(key),
    );
  }
}

/// Rust target triple for a hook's [CodeConfig].
String rustTargetTriple(CodeConfig code) {
  return switch ((code.targetOS, code.targetArchitecture)) {
    (OS.android, Architecture.arm64) => 'aarch64-linux-android',
    (OS.android, Architecture.arm) => 'armv7-linux-androideabi',
    (OS.android, Architecture.x64) => 'x86_64-linux-android',
    (OS.iOS, Architecture.arm64)
        when code.iOS.targetSdk == IOSSdk.iPhoneSimulator =>
      'aarch64-apple-ios-sim',
    (OS.iOS, Architecture.arm64) => 'aarch64-apple-ios',
    (OS.iOS, Architecture.x64) => 'x86_64-apple-ios',
    (OS.macOS, Architecture.arm64) => 'aarch64-apple-darwin',
    (OS.macOS, Architecture.x64) => 'x86_64-apple-darwin',
    (OS.linux, Architecture.arm64) => 'aarch64-unknown-linux-gnu',
    (OS.linux, Architecture.x64) => 'x86_64-unknown-linux-gnu',
    (OS.windows, Architecture.arm64) => 'aarch64-pc-windows-msvc',
    (OS.windows, Architecture.x64) => 'x86_64-pc-windows-msvc',
    (final os, final arch) => throw UnsupportedError(
      'Unsupported target: $os on $arch',
    ),
  };
}

/// Release asset name of [libraryFile] built for [rustTriple] (cargokit's
/// naming, kept so the release layout does not change).
String remoteFileName(String rustTriple, String libraryFile) =>
    '${rustTriple}_$libraryFile';

String signatureFileName(String rustTriple, String libraryFile) =>
    '${remoteFileName(rustTriple, libraryFile)}.sig';

/// Builds or downloads the Rust library for one hook invocation and adds it
/// to [output] as the code asset [assetName].
class RustLibraryBuilder {
  const RustLibraryBuilder({
    required this.cratePath,
    required this.libraryName,
    required this.assetName,
  });

  /// Rust crate directory, relative to the Dart package root.
  final String cratePath;

  /// The `[lib] name` of the crate, e.g. `wallet_ffi`.
  final String libraryName;

  /// Dart library (relative to `lib/`) that owns the binding.
  final String assetName;

  /// Runs the build. With [usePrecompiled] null, the app's
  /// `hooks: user_defines: <package>: use_precompiled_binaries` decides, and
  /// without it precompiled binaries are used only when rustup is missing.
  Future<void> run({
    required BuildInput input,
    required BuildOutputBuilder output,
    required Logger logger,
    bool? usePrecompiled,
  }) async {
    if (!input.config.buildCodeAssets) {
      return;
    }
    final code = input.config.code;
    final linkMode = DynamicLoadingBundled();
    if (code.linkModePreference == LinkModePreference.static) {
      throw UnsupportedError('$libraryName is built as a dynamic library only');
    }
    final triple = rustTargetTriple(code);
    final packageRoot = path.fromUri(input.packageRoot);
    final libraryFile = code.targetOS.dylibFileName(libraryName);

    usePrecompiled ??= _userDefinedUsePrecompiled(input) ?? !rustupAvailable();
    if (usePrecompiled) {
      if (!precompiledSupports(code)) {
        logger.info('No precompiled binary is built for this target config');
      } else {
        final crateHash = CrateHash(
          packageRoot: packageRoot,
          manifestDir: path.join(packageRoot, cratePath),
        );
        final file = await downloadPrecompiled(
          config: PrecompiledBinariesConfig.load(packageRoot),
          crateHash: crateHash.compute(),
          rustTriple: triple,
          libraryFile: libraryFile,
          cacheDir: path.join(
            path.fromUri(input.outputDirectoryShared),
            'precompiled',
          ),
          logger: logger,
        );
        if (file != null) {
          output.dependencies.addAll(crateHash.files().map((f) => f.uri));
          output.assets.code.add(
            CodeAsset(
              package: input.packageName,
              name: assetName,
              linkMode: linkMode,
              file: file.uri,
            ),
          );
          return;
        }
      }
      logger.info('Building $libraryName for $triple with cargo instead');
    }

    await FlutterRustBridgeNativeAssetsBuilder(
      cratePath: cratePath,
      assetName: assetName,
      extraCargoEnvironmentVariables: deploymentTargetEnvironment(code),
    ).run(input: input, output: output, logger: logger);

    if (_pageSizeTargets.contains(triple)) {
      for (final asset in output.build().assets.code) {
        checkAndroidPageAlignment(File.fromUri(asset.file!));
      }
    }
  }

  bool? _userDefinedUsePrecompiled(BuildInput input) {
    final value = input.userDefines['use_precompiled_binaries'];
    return switch (value) {
      null => null,
      bool() => value,
      'true' || '1' || 'yes' || 'on' => true,
      'false' || '0' || 'no' || 'off' => false,
      _ => throw FormatException(
        'use_precompiled_binaries must be true or false, got $value',
      ),
    };
  }
}

/// Whether a precompiled binary can serve [code]: Android, iOS and macOS
/// builds at or above the `precompiled*` minimums, and Linux and Windows.
/// A repository need not publish every target; a missing binary falls back
/// to a local build.
bool precompiledSupports(CodeConfig code) {
  return switch (code.targetOS) {
    OS.android => code.android.targetNdkApi >= precompiledAndroidNdkApi,
    OS.iOS => code.iOS.deploymentVersion.major >= precompiledIOSVersion,
    OS.macOS => code.macOS.deploymentVersion.major >= precompiledMacOSVersion,
    OS.linux || OS.windows => true,
    _ => false,
  };
}

/// Deployment target variables for Apple builds; native_toolchain_rust does
/// not set them, so rustc would otherwise use its own defaults.
Map<String, String> deploymentTargetEnvironment(CodeConfig code) {
  return switch (code.targetOS) {
    OS.iOS => {
      'IPHONEOS_DEPLOYMENT_TARGET': _appleVersion(code.iOS.deploymentVersion),
    },
    OS.macOS => {
      'MACOSX_DEPLOYMENT_TARGET': _appleVersion(code.macOS.deploymentVersion),
    },
    _ => const {},
  };
}

String _appleVersion(AppleVersion version) =>
    '${version.major}.${version.minor}';

/// Whether rustup can be found the way native_toolchain_rust looks for it:
/// on PATH, else in `$CARGO_HOME/bin` or `~/.cargo/bin`.
bool rustupAvailable() {
  final env = Platform.environment;
  final exe = Platform.isWindows ? 'rustup.exe' : 'rustup';
  final home = env['HOME'] ?? env['USERPROFILE'];
  final dirs = [
    ...?env['PATH']?.split(Platform.isWindows ? ';' : ':'),
    if (env['CARGO_HOME'] case final cargoHome?) path.join(cargoHome, 'bin'),
    if (home != null) path.join(home, '.cargo', 'bin'),
  ];
  return dirs.any(
    (dir) => dir.isNotEmpty && File(path.join(dir, exe)).existsSync(),
  );
}

/// Downloads `<urlPrefix><crateHash>/<triple>_<libraryFile>` and its `.sig`
/// into [cacheDir] and returns the verified file, or null if the release has
/// no such binary or its signature does not verify.
Future<File?> downloadPrecompiled({
  required PrecompiledBinariesConfig config,
  required String crateHash,
  required String rustTriple,
  required String libraryFile,
  required String cacheDir,
  required Logger logger,
}) async {
  // The file keeps the library's own name: Flutter derives the Android
  // jniLibs entry and the Apple framework name from it.
  final target = File(path.join(cacheDir, crateHash, rustTriple, libraryFile));
  if (target.existsSync()) {
    return target;
  }
  final base = '${config.urlPrefix}$crateHash/';
  final binaryUrl = Uri.parse(base + remoteFileName(rustTriple, libraryFile));
  final signatureUrl = Uri.parse(
    base + signatureFileName(rustTriple, libraryFile),
  );

  final signature = await _get(signatureUrl, logger);
  if (signature == null) {
    logger.warning('No precompiled binary for crate hash $crateHash');
    return null;
  }
  final binary = await _get(binaryUrl, logger);
  if (binary == null) {
    return null;
  }
  if (!ed.verify(config.publicKey, binary, signature)) {
    logger.severe('Signature verification failed for $binaryUrl; ignoring it');
    return null;
  }
  target.parent.createSync(recursive: true);
  final partial = File('${target.path}.part')..writeAsBytesSync(binary);
  partial.renameSync(target.path);
  logger.info('Using precompiled binary $binaryUrl');
  return target;
}

Future<Uint8List?> _get(Uri url, Logger logger) async {
  const maxAttempts = 5;
  for (var attempt = 1; ; attempt++) {
    try {
      final response = await http.get(url);
      if (response.statusCode == 200) {
        return response.bodyBytes;
      }
      if (response.statusCode != 404) {
        logger.warning('Downloading $url failed: ${response.statusCode}');
      }
      return null;
    } on Exception catch (e) {
      if (attempt == maxAttempts) {
        logger.warning('Downloading $url failed: $e');
        return null;
      }
      await Future<void>.delayed(Duration(seconds: attempt));
    }
  }
}

/// Throws unless every `PT_LOAD` segment of the 64-bit ELF [library] is
/// aligned to at least 16 KB, as Google Play requires for Android 15+.
///
/// native_toolchain_rust adds the linker flag, but silently skips it when
/// RUSTFLAGS or a Cargo config sets rustflags, so the result is checked.
void checkAndroidPageAlignment(File library) {
  final bytes = library.readAsBytesSync();
  final data = ByteData.sublistView(bytes);
  const elfMagic = [0x7f, 0x45, 0x4c, 0x46];
  if (bytes.length < 64 ||
      !const ListEquality<int>().equals(bytes.sublist(0, 4), elfMagic)) {
    throw StateError('${library.path} is not an ELF file');
  }
  if (bytes[4] != 2 || bytes[5] != 1) {
    throw StateError('${library.path} is not a 64-bit little-endian ELF');
  }
  const le = Endian.little;
  final phoff = data.getUint64(0x20, le);
  final phentsize = data.getUint16(0x36, le);
  final phnum = data.getUint16(0x38, le);
  const ptLoad = 1;
  for (var i = 0; i < phnum; i++) {
    final header = phoff + i * phentsize;
    if (data.getUint32(header, le) != ptLoad) {
      continue;
    }
    final align = data.getUint64(header + 0x30, le);
    if (align < _pageSize) {
      throw StateError(
        '${library.path}: LOAD segment aligned to $align bytes, needs '
        '$_pageSize for Android 16 KB pages. Add '
        '-C link-arg=-Wl,-z,max-page-size=$_pageSize to your rustflags.',
      );
    }
  }
}

/// Hash identifying the source a precompiled binary was built from.
///
/// Ported from cargokit's crate_hash.dart, including the local override that
/// hashes every workspace member: the FFI crate depends on sibling crates, so
/// hashing only its own directory would reuse stale binaries. It also covers
/// the files that change how the binary is built.
class CrateHash {
  CrateHash({required this.packageRoot, required this.manifestDir});

  final String packageRoot;
  final String manifestDir;

  /// Build settings that are not in any hashed file.
  static const recipe =
      'android_ndk_api=$precompiledAndroidNdkApi;'
      'ios=$precompiledIOSVersion;'
      'macos=$precompiledMacOSVersion';

  /// 128-bit hex hash over [files], line by line so that checkouts with
  /// converted line endings hash the same.
  String compute() {
    final output = AccumulatorSink<Digest>();
    final input = sha256.startChunkedConversion(output);
    input.add(utf8.encode(recipe));
    for (final file in files()) {
      for (final line in const LineSplitter().convert(
        file.readAsStringSync(),
      )) {
        input.add(utf8.encode(line));
      }
    }
    input.close();
    return hex.encode(output.events.single.bytes.sublist(0, 16));
  }

  /// The hashed files, sorted by path.
  List<File> files() {
    final files = <File>[];
    final packageDirs = <String>{path.normalize(path.absolute(manifestDir))};

    final workspaceRoot = _findWorkspaceRoot();
    if (workspaceRoot != null) {
      packageDirs.addAll(_workspaceMemberDirs(workspaceRoot));
      _addFile(files, path.join(workspaceRoot, 'Cargo.toml'));
      _addFile(files, path.join(workspaceRoot, 'Cargo.lock'));
    }

    for (final packageDir in packageDirs) {
      final src = Directory(path.join(packageDir, 'src'));
      if (src.existsSync()) {
        files.addAll(
          src.listSync(recursive: true, followLinks: false).whereType<File>(),
        );
      }
      _addFile(files, path.join(packageDir, 'Cargo.toml'));
      _addFile(files, path.join(packageDir, 'Cargo.lock'));
      _addFile(files, path.join(packageDir, 'build.rs'));
    }
    _addFile(files, path.join(manifestDir, 'rust-toolchain.toml'));
    _addFile(files, path.join(packageRoot, PrecompiledBinariesConfig.fileName));

    return files
        .groupListsBy((file) => path.normalize(path.absolute(file.path)))
        .values
        .map((group) => group.first)
        .sortedBy((file) => path.normalize(path.absolute(file.path)));
  }

  void _addFile(List<File> files, String filePath) {
    final file = File(filePath);
    if (file.existsSync()) {
      files.add(file);
    }
  }

  String? _findWorkspaceRoot() {
    var current = Directory(path.normalize(path.absolute(manifestDir)));
    while (true) {
      final manifest = File(path.join(current.path, 'Cargo.toml'));
      if (manifest.existsSync() &&
          TomlDocument.parse(manifest.readAsStringSync()).toMap()['workspace']
              is Map) {
        return current.path;
      }
      final parent = current.parent;
      if (parent.path == current.path) {
        return null;
      }
      current = parent;
    }
  }

  List<String> _workspaceMemberDirs(String workspaceRoot) {
    final manifest = TomlDocument.parse(
      File(path.join(workspaceRoot, 'Cargo.toml')).readAsStringSync(),
    ).toMap();
    final workspace = manifest['workspace'];
    final members = workspace is Map ? workspace['members'] : null;
    if (members is! List) {
      return const [];
    }
    return members
        .whereType<String>()
        .expand((member) => _expandWorkspaceMember(workspaceRoot, member))
        .toList();
  }

  Iterable<String> _expandWorkspaceMember(String workspaceRoot, String member) {
    bool isCrate(String dir) => File(path.join(dir, 'Cargo.toml')).existsSync();
    if (!member.contains('*')) {
      final dir = path.normalize(path.join(workspaceRoot, member));
      return isCrate(dir) ? [dir] : const [];
    }
    if (!member.endsWith('/*')) {
      return const [];
    }
    final base = Directory(
      path.join(workspaceRoot, member.substring(0, member.length - 2)),
    );
    if (!base.existsSync()) {
      return const [];
    }
    return base
        .listSync(followLinks: false)
        .whereType<Directory>()
        .map((dir) => path.normalize(dir.path))
        .where(isCrate);
  }
}
