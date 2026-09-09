/// This is copied from Cargokit (which is the official way to use it currently)
/// Details: https://fzyzcjy.github.io/flutter_rust_bridge/manual/integrate/builtin

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as path;
import 'package:toml/toml.dart';

class CrateHash {
  /// Computes a hash uniquely identifying crate content.
  ///
  /// For workspace crates this also includes workspace package sources and the
  /// root Cargo manifest/lockfile. The FFI crate depends on sibling crates, so
  /// hashing only the FFI crate directory can otherwise reuse stale binaries.
  ///
  /// If [tempStorage] is provided, computed hash is stored in a file in that directory
  /// and reused on subsequent calls if the crate content hasn't changed.
  static String compute(String manifestDir, {String? tempStorage}) {
    return CrateHash._(
      manifestDir: manifestDir,
      tempStorage: tempStorage,
    )._compute();
  }

  CrateHash._({required this.manifestDir, required this.tempStorage});

  String _compute() {
    final files = getFiles();
    final tempStorage = this.tempStorage;
    if (tempStorage != null) {
      final quickHash = _computeQuickHash(files);
      final quickHashFolder = Directory(path.join(tempStorage, 'crate_hash'));
      quickHashFolder.createSync(recursive: true);
      final quickHashFile = File(path.join(quickHashFolder.path, quickHash));
      if (quickHashFile.existsSync()) {
        return quickHashFile.readAsStringSync();
      }
      final hash = _computeHash(files);
      quickHashFile.writeAsStringSync(hash);
      return hash;
    } else {
      return _computeHash(files);
    }
  }

  /// Computes a quick hash based on files stat (without reading contents). This
  /// is used to cache the real hash, which is slower to compute since it involves
  /// reading every single file.
  String _computeQuickHash(List<File> files) {
    final output = AccumulatorSink<Digest>();
    final input = sha256.startChunkedConversion(output);

    final data = ByteData(8);
    for (final file in files) {
      input.add(utf8.encode(file.path));
      final stat = file.statSync();
      data.setUint64(0, stat.size);
      input.add(data.buffer.asUint8List());
      data.setUint64(0, stat.modified.millisecondsSinceEpoch);
      input.add(data.buffer.asUint8List());
    }

    input.close();
    return base64Url.encode(output.events.single.bytes);
  }

  String _computeHash(List<File> files) {
    final output = AccumulatorSink<Digest>();
    final input = sha256.startChunkedConversion(output);

    void addTextFile(File file) {
      // text Files are hashed by lines in case we're dealing with github checkout
      // that auto-converts line endings.
      final splitter = LineSplitter();
      if (file.existsSync()) {
        final data = file.readAsStringSync();
        final lines = splitter.convert(data);
        for (final line in lines) {
          input.add(utf8.encode(line));
        }
      }
    }

    for (final file in files) {
      addTextFile(file);
    }

    input.close();
    final res = output.events.single;

    // Truncate to 128bits.
    final hash = res.bytes.sublist(0, 16);
    return hex.encode(hash);
  }

  List<File> getFiles() {
    final files = <File>[];
    final packageDirs = <String>{path.normalize(path.absolute(manifestDir))};

    final workspaceRoot = _findWorkspaceRoot();
    if (workspaceRoot != null) {
      packageDirs.addAll(_workspaceMemberDirs(workspaceRoot));
      _addFile(files, path.join(workspaceRoot, 'Cargo.toml'));
      _addFile(files, path.join(workspaceRoot, 'Cargo.lock'));
    }

    for (final packageDir in packageDirs) {
      _addSourceFiles(files, packageDir);
      _addFile(files, path.join(packageDir, 'Cargo.toml'));
      _addFile(files, path.join(packageDir, 'Cargo.lock'));
      _addFile(files, path.join(packageDir, 'build.rs'));
      _addFile(files, path.join(packageDir, 'cargokit.yaml'));
    }

    final uniqueFiles = files
        .groupListsBy((file) => path.normalize(path.absolute(file.path)))
        .values
        .map((files) => files.first)
        .toList();
    uniqueFiles.sortBy((element) => element.path);
    return uniqueFiles;
  }

  void _addSourceFiles(List<File> files, String packageDir) {
    final src = Directory(path.join(packageDir, 'src'));
    if (src.existsSync()) {
      files.addAll(
        src.listSync(recursive: true, followLinks: false).whereType<File>(),
      );
    }
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
      final manifestFile = File(path.join(current.path, 'Cargo.toml'));
      if (manifestFile.existsSync()) {
        final manifest = TomlDocument.parse(manifestFile.readAsStringSync());
        if (manifest.toMap()['workspace'] is Map) {
          return current.path;
        }
      }

      final parent = current.parent;
      if (parent.path == current.path) {
        return null;
      }
      current = parent;
    }
  }

  List<String> _workspaceMemberDirs(String workspaceRoot) {
    final manifestFile = File(path.join(workspaceRoot, 'Cargo.toml'));
    final manifest = TomlDocument.parse(manifestFile.readAsStringSync());
    final workspace = manifest.toMap()['workspace'];
    if (workspace is! Map) {
      return [];
    }

    final members = workspace['members'];
    if (members is! List) {
      return [];
    }

    return members
        .whereType<String>()
        .expand((member) => _expandWorkspaceMember(workspaceRoot, member))
        .toList(growable: false);
  }

  Iterable<String> _expandWorkspaceMember(String workspaceRoot, String member) {
    if (!member.contains('*')) {
      final memberDir = path.normalize(path.join(workspaceRoot, member));
      if (File(path.join(memberDir, 'Cargo.toml')).existsSync()) {
        return [memberDir];
      }
      return const [];
    }

    if (!member.endsWith('/*')) {
      return const [];
    }

    final baseDir = Directory(
      path.normalize(
        path.join(workspaceRoot, member.substring(0, member.length - 2)),
      ),
    );
    if (!baseDir.existsSync()) {
      return const [];
    }

    return baseDir
        .listSync(followLinks: false)
        .whereType<Directory>()
        .where((dir) => File(path.join(dir.path, 'Cargo.toml')).existsSync())
        .map((dir) => path.normalize(dir.path));
  }

  final String manifestDir;
  final String? tempStorage;
}
