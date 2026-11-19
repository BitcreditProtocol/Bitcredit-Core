// Builds the Rust FFI library as a Dart/Flutter code asset, preferring a
// signed precompiled binary over a local cargo build.
//
// Replaces cargokit's build_tool (artifacts_provider, crate_hash, options) and
// is shared by hook/build.dart (app builds) and tool/precompile_binaries.dart
// (CI release builds), so both produce a binary the same way.
//
// Nothing in this file is specific to one repository; hook/build.dart passes
// the crate path and library name.

import 'dart:async';
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
/// iOS and macOS match the constants flutter_tools passes to every build hook
/// (`targetIOSVersion` 15, `targetMacOSVersion` 13), whatever deployment
/// target the app declares; the library, precompiled or built locally,
/// needs at least those versions. Android matches Flutter's default
/// `minSdk`; the hook gets the app's own `minSdk`, and an app below 24
/// (Flutter accepts 23) builds locally with cargo instead. They are part of
/// the crate hash, so changing one publishes new binaries.
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
  /// [locked] passes `--locked` to cargo, so a `Cargo.lock` that does not
  /// match the manifests fails the build instead of being rewritten.
  Future<void> run({
    required BuildInput input,
    required BuildOutputBuilder output,
    required Logger logger,
    bool? usePrecompiled,
    bool locked = false,
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

    final crateHash = CrateHash(
      packageRoot: packageRoot,
      manifestDir: path.join(packageRoot, cratePath),
    );
    // Rerun the hook when a file is added to a crate: a directory dependency
    // is hashed by its entries, a file dependency only covers files that
    // already exist (and cargo's dep-info lists only what it read).
    output.dependencies.addAll(crateHash.directories().map((d) => d.uri));

    usePrecompiled ??= _userDefinedUsePrecompiled(input) ?? !rustupAvailable();
    if (usePrecompiled) {
      if (!precompiledSupports(code)) {
        logger.info('No precompiled binary is built for this target config');
      } else {
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
        if (file != null && _pageAligned(file, triple, logger)) {
          logger.info('Using precompiled binary ${file.path}');
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
      extraCargoBuildArgs: [if (locked) '--locked'],
      extraCargoEnvironmentVariables: deploymentTargetEnvironment(code),
    ).run(input: input, output: output, logger: logger);

    if (_pageSizeTargets.contains(triple)) {
      for (final asset in output.build().assets.code) {
        checkAndroidPageAlignment(File.fromUri(asset.file!));
      }
    }
  }

  /// Whether a downloaded [file] passes the 16 KB page check for [triple];
  /// a failure is logged and the caller builds with cargo instead.
  bool _pageAligned(File file, String triple, Logger logger) {
    if (!_pageSizeTargets.contains(triple)) {
      return true;
    }
    try {
      checkAndroidPageAlignment(file);
      return true;
    } on StateError catch (e) {
      logger.severe('Ignoring precompiled binary: ${e.message}');
      return false;
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

/// Whether rustup can be found where native_toolchain_rust looks for it:
/// on PATH, else in `.cargo/bin` under `HOME` (`USERPROFILE` on Windows).
bool rustupAvailable() {
  final env = Platform.environment;
  final exe = Platform.isWindows ? 'rustup.exe' : 'rustup';
  final home = Platform.isWindows ? env['USERPROFILE'] : env['HOME'];
  final dirs = [
    ...?env['PATH']?.split(Platform.isWindows ? ';' : ':'),
    if (home != null) path.join(home, '.cargo', 'bin'),
  ];
  return dirs.any(
    (dir) => dir.isNotEmpty && File(path.join(dir, exe)).existsSync(),
  );
}

/// Downloads `<urlPrefix><crateHash>/<triple>_<libraryFile>` and its `.sig`
/// into [cacheDir] and returns the verified file, or null if the release has
/// no such binary, cannot be reached or its signature does not verify; the
/// caller then builds with cargo. A cached copy is verified against its
/// cached `.sig` on every reuse and downloaded again if that fails.
///
/// A request is abandoned when no response headers, or no body data, arrive
/// for [idleTimeout]; a slow but progressing download is never cut off.
/// Timeouts, network errors, HTTP 429 and 5xx are retried up to
/// [maxAttempts] times.
Future<File?> downloadPrecompiled({
  required PrecompiledBinariesConfig config,
  required String crateHash,
  required String rustTriple,
  required String libraryFile,
  required String cacheDir,
  required Logger logger,
  Duration idleTimeout = const Duration(seconds: 30),
  int maxAttempts = 3,
}) async {
  // The file keeps the library's own name: Flutter derives the Android
  // jniLibs entry and the Apple framework name from it.
  final target = File(path.join(cacheDir, crateHash, rustTriple, libraryFile));
  final cachedSignature = File('${target.path}.sig');
  if (target.existsSync()) {
    if (cachedSignature.existsSync() &&
        ed.verify(
          config.publicKey,
          target.readAsBytesSync(),
          cachedSignature.readAsBytesSync(),
        )) {
      logger.info('Reusing verified cached ${target.path}');
      return target;
    }
    logger.warning('Cached ${target.path} does not verify; downloading again');
    target.deleteSync();
    if (cachedSignature.existsSync()) {
      cachedSignature.deleteSync();
    }
  }
  final base = '${config.urlPrefix}$crateHash/';
  final binaryUrl = Uri.parse(base + remoteFileName(rustTriple, libraryFile));
  final signatureUrl = Uri.parse(
    base + signatureFileName(rustTriple, libraryFile),
  );

  Future<Uint8List?> get(Uri url) =>
      _get(url, logger, idleTimeout: idleTimeout, maxAttempts: maxAttempts);

  final signature = await get(signatureUrl);
  if (signature == null) {
    logger.warning('No precompiled binary for crate hash $crateHash');
    return null;
  }
  final binary = await get(binaryUrl);
  if (binary == null) {
    return null;
  }
  if (!ed.verify(config.publicKey, binary, signature)) {
    logger.severe('Signature verification failed for $binaryUrl; ignoring it');
    return null;
  }
  target.parent.createSync(recursive: true);
  // Signature first: a binary without one is never reused.
  File('${cachedSignature.path}.part')
    ..writeAsBytesSync(signature)
    ..renameSync(cachedSignature.path);
  File('${target.path}.part')
    ..writeAsBytesSync(binary)
    ..renameSync(target.path);
  logger.info('Downloaded and verified $binaryUrl');
  return target;
}

/// GETs [url]; null on 404 (no binary) or once retries are exhausted.
Future<Uint8List?> _get(
  Uri url,
  Logger logger, {
  required Duration idleTimeout,
  required int maxAttempts,
}) async {
  for (var attempt = 1; ; attempt++) {
    String failure;
    // A fresh client per attempt: closing it aborts a stalled request.
    final client = http.Client();
    try {
      final response = await client
          .send(http.Request('GET', url))
          .timeout(idleTimeout);
      final status = response.statusCode;
      if (status == 200) {
        // The timeout applies to each gap between chunks, not the total.
        final body = BytesBuilder(copy: false);
        await response.stream.timeout(idleTimeout).forEach(body.add);
        return body.takeBytes();
      }
      if (status == 404) {
        return null;
      }
      if (status != 429 && status < 500) {
        logger.warning('Downloading $url failed: HTTP $status');
        return null;
      }
      failure = 'HTTP $status';
    } on TimeoutException {
      failure = 'no data for ${idleTimeout.inSeconds}s';
    } on Exception catch (e) {
      failure = '$e';
    } finally {
      client.close();
    }
    if (attempt >= maxAttempts) {
      logger.warning('Downloading $url failed: $failure; giving up');
      return null;
    }
    logger.info('Downloading $url failed: $failure; retrying');
    await Future<void>.delayed(Duration(seconds: 1 << (attempt - 1)));
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
        '$_pageSize for Android 16 KB pages. native_toolchain_rust adds '
        '-C link-arg=-Wl,-z,max-page-size=$_pageSize only when no rustflags '
        'are set; a Cargo config or CARGO_ENCODED_RUSTFLAGS, '
        'CARGO_BUILD_RUSTFLAGS or CARGO_TARGET_<TRIPLE>_RUSTFLAGS sets them, '
        'so add the flag there. Build hooks do not receive RUSTFLAGS.',
      );
    }
  }
}

/// Hash identifying the source a precompiled binary was built from.
///
/// Any file that can change the compiled library must change the hash: a
/// stale hash makes apps download a binary built from older sources. So it
/// covers every file in every workspace member's directory (not only `src/`:
/// `include_str!`, `sqlx::migrate!` and build scripts read other files), the
/// workspace `Cargo.toml`/`Cargo.lock` and `.cargo/config.toml`, the FFI
/// crate's `rust-toolchain.toml`, `precompiled_binaries.yaml` and [recipe].
/// Hashing too much only costs a cargo build; hashing too little ships stale
/// code. Started from cargokit's crate_hash.dart and its local override
/// that hashes all workspace members.
class CrateHash {
  CrateHash({required this.packageRoot, required this.manifestDir});

  final String packageRoot;
  final String manifestDir;

  /// Build settings that are not in any hashed file.
  static const recipe =
      'android_ndk_api=$precompiledAndroidNdkApi;'
      'ios=$precompiledIOSVersion;'
      'macos=$precompiledMacOSVersion';

  /// 128-bit hex hash over [recipe] and, per file in [files], its path
  /// relative to [_hashRoot] (so a rename or an empty new file counts) and
  /// its content. UTF-8 text is hashed line by line so that checkouts with
  /// converted line endings agree; other files are hashed as raw bytes.
  String compute() {
    final output = AccumulatorSink<Digest>();
    final input = sha256.startChunkedConversion(output)
      ..add(utf8.encode('$recipe\n'));
    for (final (hashed, file) in _entries()) {
      input.add(utf8.encode('$hashed\u0000${_contentDigest(file)}\n'));
    }
    input.close();
    return hex.encode(output.events.single.bytes.sublist(0, 16));
  }

  /// [file]'s path relative to [root] with `/` separators, whatever the
  /// host's [context]. Files are hashed and ordered by it, so a checkout
  /// hashes the same on Windows as on Linux and macOS.
  static String hashPath(String file, String root, {path.Context? context}) {
    final p = context ?? path.context;
    return p.split(p.relative(file, from: root)).join('/');
  }

  static String _contentDigest(File file) {
    final bytes = file.readAsBytesSync();
    String text;
    try {
      text = utf8.decode(bytes);
    } on FormatException {
      return 'bin:${sha256.convert(bytes)}';
    }
    final lines = const LineSplitter().convert(text).join('\n');
    return 'txt:${sha256.convert(utf8.encode(lines))}';
  }

  /// Directory the hashed paths are relative to: the workspace root, or the
  /// crate itself outside a workspace.
  String _hashRoot() =>
      _findWorkspaceRoot() ?? path.normalize(path.absolute(manifestDir));

  /// The hashed files, in hashing order.
  List<File> files() => [for (final (_, file) in _entries()) file];

  /// The directories whose entries are hashed: each workspace member and
  /// every directory [files] walks below it, plus an existing `.cargo/` at
  /// the workspace root. Not the workspace root itself, whose listing
  /// changes when cargo creates `target/` there.
  List<Directory> directories() {
    final dirs = <String, Directory>{};
    void add(Directory dir) =>
        dirs.putIfAbsent(path.normalize(path.absolute(dir.path)), () => dir);
    final workspaceRoot = _findWorkspaceRoot();
    final packageDirs = <String>{
      path.normalize(path.absolute(manifestDir)),
      if (workspaceRoot != null) ..._workspaceMemberDirs(workspaceRoot),
    };
    if (workspaceRoot != null) {
      final cargoDir = Directory(path.join(workspaceRoot, '.cargo'));
      if (cargoDir.existsSync()) {
        add(cargoDir);
      }
    }
    for (final packageDir in packageDirs) {
      final dir = Directory(packageDir);
      add(dir);
      _walk(dir, onDirectory: add);
    }
    return dirs.values.toList();
  }

  /// The hashed files with their [hashPath], sorted by it.
  List<(String, File)> _entries() {
    final files = <String, File>{};
    void add(File file) =>
        files.putIfAbsent(path.normalize(path.absolute(file.path)), () => file);
    void addIfExists(String filePath) {
      final file = File(filePath);
      if (file.existsSync()) {
        add(file);
      }
    }

    final packageDirs = <String>{path.normalize(path.absolute(manifestDir))};
    final workspaceRoot = _findWorkspaceRoot();
    if (workspaceRoot != null) {
      packageDirs.addAll(_workspaceMemberDirs(workspaceRoot));
      for (final name in [
        'Cargo.toml',
        'Cargo.lock',
        'rust-toolchain.toml',
        'rust-toolchain',
        path.join('.cargo', 'config.toml'),
        path.join('.cargo', 'config'),
      ]) {
        addIfExists(path.join(workspaceRoot, name));
      }
    }
    for (final packageDir in packageDirs) {
      _walk(Directory(packageDir), onFile: add);
    }
    addIfExists(path.join(packageRoot, PrecompiledBinariesConfig.fileName));

    final root = _hashRoot();
    return [
      for (final MapEntry(:key, :value) in files.entries)
        (hashPath(key, root), value),
    ]..sort((a, b) => a.$1.compareTo(b.$1));
  }

  /// Visits every file and directory under a member crate's [dir], except
  /// build output (`target/`) and hidden entries other than `.cargo/`,
  /// which can hold a Cargo config. Symlinked files are followed, symlinked
  /// directories not.
  static void _walk(
    Directory dir, {
    void Function(File)? onFile,
    void Function(Directory)? onDirectory,
  }) {
    for (final entity in dir.listSync(followLinks: false)) {
      final name = path.basename(entity.path);
      if (name == 'target' || (name.startsWith('.') && name != '.cargo')) {
        continue;
      }
      if (entity is Directory) {
        onDirectory?.call(entity);
        _walk(entity, onFile: onFile, onDirectory: onDirectory);
      } else if (entity is File) {
        onFile?.call(entity);
      } else if (entity is Link && FileSystemEntity.isFileSync(entity.path)) {
        onFile?.call(File(entity.path));
      }
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
