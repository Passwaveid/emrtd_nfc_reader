/// Repository hygiene the release depends on.
///
/// These assertions are about files, not behaviour, and they live in the
/// package's own suite because that is what CI runs on every push. Each one
/// exists because breaking it is silent: a stale `publish_to`, a `.pubignore`
/// that stops excluding a 26 MB directory, a README link that rots when a
/// file moves, a link into a directory that is not published.
///
/// Runs with the package root as the working directory, like
/// `read_quirks_test.dart` reading `pubspec.yaml`.
library;

import 'dart:convert';
import 'dart:io';

import 'package:emrtd_core/src/version.dart';
import 'package:flutter_test/flutter_test.dart';

// ignore_for_file: implementation_imports

/// The package's repository. Its organisation name is the one place a
/// product name legitimately appears in a published artefact (a package
/// must name its own repository), so the consumer-name sweep below excises
/// this string before scanning, and catches everything else.
const repositoryUrl = 'https://github.com/passwaveid/emrtd_nfc_reader';

/// Every rule `.pubignore` must carry. The first group restates
/// what the root `.gitignore` would have excluded: a `.pubignore` REPLACES
/// the `.gitignore` for its directory rather than adding to it, so dropping
/// one of these ships a build tree. The second is the maintainer material an
/// integrator never runs.
const requiredPubignoreRules = [
  'build/',
  'coverage/',
  'upstream/',
  'swift-runner/.upstream-build/',
  'swift-runner/session-*',
  '*.log',
  'TEST*.xml',
  'node_modules/',
  'dist/',
  'target/',
  'documents/',
  'plans/',
  'conformance/',
  'test/',
  'swift-runner/',
  '/*.yml',
];

/// Directories that are never published: the plans and the
/// specification texts.
const privateDirectories = ['plans', 'documents'];

final _linkPattern = RegExp(r'\[[^\]]*\]\(\s*<?([^)>\s]+)>?\s*\)');

Iterable<String> _linkTargets(String markdown) =>
    _linkPattern.allMatches(markdown).map((m) => m.group(1)!);

bool _isExternal(String target) =>
    target.startsWith('http://') ||
    target.startsWith('https://') ||
    target.startsWith('mailto:') ||
    target.startsWith('#');

/// The repository path [target] names when [doc] links to it, with `.` and
/// `..` resolved, or null when it climbs out of the repository.
String? _resolveLink(String doc, String target) {
  final path = Uri.parse(
    'file:///repo/$doc',
  ).resolve(target.split('#').first).path;
  return path.startsWith('/repo/') ? path.substring('/repo/'.length) : null;
}

List<File> _dartAndTextFilesUnder(String dir) => Directory(dir)
    .listSync(recursive: true)
    .whereType<File>()
    // Dot-directories and build output never reach a tarball or a reader.
    .where((f) => !f.path.split('/').any((seg) => seg.startsWith('.')))
    .where((f) => !f.path.contains('/build/'))
    .where((f) => !_isSessionArtefact(f.path))
    .where(
      (f) => const {
        '.dart',
        '.md',
        '.yaml',
        '.yml',
        '.plist',
        '.xml',
        '.entitlements',
      }.any((ext) => f.path.endsWith(ext)),
    )
    .toList();

// Built from code points: this file is scanned too, so any of these
// characters, or its escape, written out here would flag itself.
final _bannedCharacters = {
  'em dash': _literalOrEscaped(0x2014),
  'en dash': _literalOrEscaped(0x2013),
  'minus sign': _literalOrEscaped(0x2212),
};

RegExp _literalOrEscaped(int codePoint) => RegExp(
  '${RegExp.escape(String.fromCharCode(codePoint))}'
  r'|\\u\{?'
  '${codePoint.toRadixString(16)}'
  r'\}?',
  caseSensitive: false,
);

List<(int, String)> _bannedCharacterLines(String text) {
  final lines = const LineSplitter().convert(text);
  return [
    for (var i = 0; i < lines.length; i++)
      for (final MapEntry(key: name, value: pattern)
          in _bannedCharacters.entries)
        if (pattern.hasMatch(lines[i])) (i + 1, name),
  ];
}

bool _isPrivate(String path) =>
    privateDirectories.any((dir) => path.startsWith('$dir/'));

/// Swift-runner session output (`swift-runner/session-*`, which git and
/// `.pubignore` both ignore) is never committed, so no scan reads it.
bool _isSessionArtefact(String path) =>
    path.split('/').any((seg) => seg.startsWith('session-'));

bool _inDotDirectory(String path) {
  final segments = path.split('/');
  return segments
      .take(segments.length - 1)
      .any((segment) => segment.startsWith('.'));
}

List<String> _trackedFiles(String root) {
  final listing = Process.runSync('git', [
    '-C',
    root,
    '-c',
    'safe.directory=$root',
    'ls-files',
    '-z',
  ]);
  if (listing.exitCode != 0) {
    throw StateError('git ls-files failed in $root: ${listing.stderr}');
  }
  return (listing.stdout as String)
      .split('\x00')
      .where((path) => path.isNotEmpty)
      .toList();
}

String? _readUtf8(File file) {
  try {
    return utf8.decode(file.readAsBytesSync());
  } on FormatException {
    return null;
  }
}

void main() {
  group('release hygiene', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();

    test('pubspec declares no publish_to', () {
      // A commented-out `# publish_to:` is fine; a live one at column 0
      // silently makes every publish a no-op.
      expect(
        RegExp(r'^publish_to:', multiLine: true).hasMatch(pubspec),
        isFalse,
      );
    });

    test('pubspec points at a public repository', () {
      expect(
        RegExp(
          r'^repository:\s*https://github\.com/',
          multiLine: true,
        ).hasMatch(pubspec),
        isTrue,
      );
      expect(
        RegExp(r'^homepage:\s*https://', multiLine: true).hasMatch(pubspec),
        isTrue,
      );
    });

    test('the README installs from the repository', () {
      expect(
        File('README.md').readAsStringSync(),
        contains('git: $repositoryUrl.git'),
      );
    });

    group('.pubignore', () {
      final file = File('.pubignore');

      test('exists', () => expect(file.existsSync(), isTrue));

      final lines = file
          .readAsLinesSync()
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty && !l.startsWith('#'))
          .toList();

      for (final rule in requiredPubignoreRules) {
        test('carries "$rule"', () => expect(lines, contains(rule)));
      }

      test('does not hide the example or the library itself', () {
        for (final essential in ['example/', 'lib/', 'example', 'lib']) {
          expect(
            lines,
            isNot(contains(essential)),
            reason: 'the tarball is worthless without $essential',
          );
        }
      });
    });

    group('CHANGELOG', () {
      final headings = File(
        'CHANGELOG.md',
      ).readAsLinesSync().where((l) => l.startsWith('## ')).toList();

      test('the top heading is the current version', () {
        // Catches a version bump that never got an entry.
        expect(headings.first, startsWith('## $emrtdCoreVersion'));
      });

      test('no heading is still marked unreleased', () {
        expect(headings.where((h) => h.contains('(unreleased)')), isEmpty);
      });
    });

    group('example', () {
      final examplePubspec = File('example/pubspec.yaml').readAsStringSync();

      test('depends on the parent by path', () {
        expect(
          RegExp(
            r'emrtd_core:\s*\n\s*path:\s*\.\.?/?',
            multiLine: true,
          ).hasMatch(examplePubspec),
          isTrue,
        );
      });

      test('has the entry point pub.dev renders as the Example tab', () {
        expect(File('example/lib/main.dart').existsSync(), isTrue);
      });

      test('declares no NFC plugin of its own', () {
        // Holding the plugin and this package's fork together fails the
        // Android build on a duplicate Kotlin class. NFC goes through
        // emrtd_core only.
        for (final plugin in ['flutter_nfc_kit', 'flutter_nfc_kit_isodep']) {
          expect(
            RegExp('^  $plugin:', multiLine: true).hasMatch(examplePubspec),
            isFalse,
          );
        }
      });
    });

    test('every internal README link resolves', () {
      for (final doc in [
        'README.md',
        'CONTRIBUTING.md',
        'example/README.md',
        'swift-runner/README.md',
      ]) {
        final base = doc.contains('/')
            ? doc.substring(0, doc.lastIndexOf('/'))
            : '.';
        for (final target in _linkTargets(File(doc).readAsStringSync())) {
          if (_isExternal(target)) continue;
          final path = '$base/${target.split('#').first}';
          expect(
            File(path).existsSync() || Directory(path).existsSync(),
            isTrue,
            reason: '$doc links to $target, which does not exist',
          );
        }
      }
    });

    test('a link resolves against the document that holds it', () {
      expect(_resolveLink('README.md', 'plans/a.md'), 'plans/a.md');
      expect(_resolveLink('README.md', './plans/a.md'), 'plans/a.md');
      expect(
        _resolveLink('lib/src/lds/README.md', '../../../plans/a-i.md'),
        'plans/a-i.md',
      );
      expect(
        _resolveLink('swift-runner/README.md', '../documents/x.pdf#p2'),
        'documents/x.pdf',
      );
      expect(_resolveLink('lib/src/README.md', 'b.md'), 'lib/src/b.md');
      expect(_resolveLink('lib/a.dart', 'plansx/a.md'), 'lib/plansx/a.md');
      expect(
        _resolveLink('lib/src/lds/README.md', '../../../../outside.md'),
        isNull,
      );
    });

    test('no public artefact links into a private directory', () {
      // Such a link resolves only in a tree that holds the private
      // directories, and is dead everywhere the public can reach. Prose that
      // merely names the path is fine.
      final docs = [
        'README.md',
        'CONTRIBUTING.md',
        'CHANGELOG.md',
        'UPSTREAM.md',
        ...[
          'lib',
          'conformance',
          'example',
          'swift-runner',
        ].expand(_dartAndTextFilesUnder).map((f) => f.path),
      ];
      for (final doc in docs) {
        for (final target in _linkTargets(File(doc).readAsStringSync())) {
          if (_isExternal(target)) continue;
          final resolved = _resolveLink(doc, target);
          expect(
            resolved != null && _isPrivate(resolved),
            isFalse,
            reason: '$doc links to $target',
          );
        }
      }
    });

    test('no consumer names in published artefacts', () {
      final files = [
        'README.md',
        'CONTRIBUTING.md',
        'UPSTREAM.md',
        'pubspec.yaml',
        'example/README.md',
        ...[
          'lib',
          'example/lib',
        ].expand(_dartAndTextFilesUnder).map((f) => f.path),
      ];
      for (final path in files) {
        // The repository URL is the package's own identity and has to name
        // the organisation that publishes it; everything else must read to
        // someone who has never heard of the consumer this was built for.
        final text = File(path)
            .readAsStringSync()
            .replaceAll(repositoryUrl, '')
            .replaceAll('https://github.com/passwaveid', '')
            .toLowerCase();
        expect(
          text,
          isNot(contains('passwave')),
          reason: '$path names a consumer',
        );
      }
      // CHANGELOG.md is exempt by design: history may say what was built for
      // whom. plans/ is private and never published.
    });

    group('dashes and minus signs', () {
      final emDash = String.fromCharCode(0x2014);
      final enDash = String.fromCharCode(0x2013);
      final minus = String.fromCharCode(0x2212);
      final bs = String.fromCharCode(92);

      test(
        'the detector flags each character, literal or escaped, by line',
        () {
          expect(_bannedCharacterLines(''), isEmpty);
          expect(_bannedCharacterLines('a $emDash b'), [(1, 'em dash')]);
          expect(_bannedCharacterLines('3${enDash}4'), [(1, 'en dash')]);
          expect(_bannedCharacterLines('p${minus}1'), [(1, 'minus sign')]);
          expect(_bannedCharacterLines('$enDash$enDash'), [(1, 'en dash')]);
          expect(_bannedCharacterLines('$enDash ${bs}u2013'), [(1, 'en dash')]);
          expect(_bannedCharacterLines('one\ntwo $minus\nthree'), [
            (2, 'minus sign'),
          ]);
          expect(_bannedCharacterLines('one\r\ntwo\r\n$enDash'), [
            (3, 'en dash'),
          ]);
          expect(_bannedCharacterLines('$emDash\n\n$minus\n'), [
            (1, 'em dash'),
            (3, 'minus sign'),
          ]);
          expect(_bannedCharacterLines('$minus $enDash $emDash'), [
            (1, 'em dash'),
            (1, 'en dash'),
            (1, 'minus sign'),
          ]);
          for (final (hex, name) in const [
            ('2014', 'em dash'),
            ('2013', 'en dash'),
            ('2212', 'minus sign'),
          ]) {
            for (final escape in [
              '${bs}u$hex',
              '${bs}U$hex',
              '${bs}u{$hex}',
              '${bs}U{$hex}',
            ]) {
              expect(_bannedCharacterLines('"x $escape y"'), [
                (1, name),
              ], reason: escape);
            }
          }
        },
      );

      test(
        'the detector ignores hyphens, superscript minus and near misses',
        () {
          final superscriptMinus = String.fromCharCode(0x207B);
          expect(_bannedCharacterLines('a - b -- c 3-4 p-1 -1'), isEmpty);
          expect(_bannedCharacterLines('a${superscriptMinus}1'), isEmpty);
          expect(
            _bannedCharacterLines(
              '${bs}u2015 ${bs}u{2012} u2013 0x2013 0x2212 ${bs}u201 ${bs}u221',
            ),
            isEmpty,
          );
        },
      );

      test('only paths inside a private directory are private', () {
        expect(_isPrivate('plans/a.md'), isTrue);
        expect(_isPrivate('documents/a/b.txt'), isTrue);
        expect(_isPrivate('plans'), isFalse);
        expect(_isPrivate('plansx/a.md'), isFalse);
        expect(_isPrivate('lib/plans/a.dart'), isFalse);
        expect(_isPrivate('test/release_hygiene_test.dart'), isFalse);
      });

      test('only session output is a session artefact', () {
        expect(
          _isSessionArtefact('swift-runner/session-20261004/notes.md'),
          isTrue,
        );
        expect(_isSessionArtefact('swift-runner/session-1.md'), isTrue);
        expect(_isSessionArtefact('session-x/a.md'), isTrue);
        expect(_isSessionArtefact('swift-runner/README.md'), isFalse);
        expect(_isSessionArtefact('swift-runner/sessions/a.md'), isFalse);
        expect(_isSessionArtefact('swift-runner/session/a.md'), isFalse);
        expect(_isSessionArtefact('swift-runner/my-session-1/a.md'), isFalse);
      });

      test('a failed git listing throws rather than scanning nothing', () {
        final dir = Directory.systemTemp.createTempSync('dash_guard');
        addTearDown(() => dir.deleteSync(recursive: true));
        expect(() => _trackedFiles('${dir.path}/absent'), throwsStateError);
      });

      test('files that are not UTF-8 are skipped, text is read', () {
        final dir = Directory.systemTemp.createTempSync('dash_guard');
        addTearDown(() => dir.deleteSync(recursive: true));
        final binary = File('${dir.path}/b')
          ..writeAsBytesSync([0xff, 0xfe, 0x00]);
        final text = File('${dir.path}/t')..writeAsStringSync('a $emDash b');
        expect(_readUtf8(binary), isNull);
        expect(_readUtf8(text), 'a $emDash b');
      });

      test('no tracked public file holds one', () {
        final scanned = <String>[];
        final hits = <String>[];
        final root = Directory.current.path;
        for (final path in _trackedFiles(root).where((p) => !_isPrivate(p))) {
          final text = _readUtf8(File(path));
          if (text == null) continue;
          scanned.add(path);
          hits.addAll(
            _bannedCharacterLines(
              text,
            ).map((hit) => '$path:${hit.$1} ${hit.$2}'),
          );
        }
        expect(scanned, contains('test/release_hygiene_test.dart'));
        expect(scanned.length, greaterThan(250));
        expect(hits, isEmpty, reason: 'found at:\n${hits.join('\n')}');
      });
    });

    group('dot-directories', () {
      test('a path is inside one only below a directory named with a dot', () {
        expect(_inDotDirectory('.idea/workspace.xml'), isTrue);
        expect(_inDotDirectory('example/.dart_tool/x.json'), isTrue);
        expect(_inDotDirectory('a/b/.cache/c/d.txt'), isTrue);
        expect(_inDotDirectory('.gitignore'), isFalse);
        expect(_inDotDirectory('example/.metadata'), isFalse);
        expect(_inDotDirectory('lib/a.b/c.dart'), isFalse);
        expect(_inDotDirectory('lib/src/x.dart'), isFalse);
      });

      test('no tracked file sits inside one', () {
        // Tool and editor state lives in dot-directories, and not every
        // checkout ignores all of them, so a broad `git add` can sweep one in.
        final tracked = _trackedFiles(Directory.current.path);
        expect(tracked, contains('.gitignore'));
        expect(tracked.where(_inDotDirectory), isEmpty);
      });
    });
  });
}
