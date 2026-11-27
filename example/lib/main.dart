import 'package:emrtd_core/emrtd_core.dart';
import 'package:flutter/material.dart';

import 'read_screen.dart';

void main() => runApp(const EmrtdExampleApp());

class EmrtdExampleApp extends StatelessWidget {
  const EmrtdExampleApp({super.key, this.reader});

  /// Built once and reused. `PassportReader()` with no arguments is a working
  /// reader: every parameter is optional and the NFC session defaults to the
  /// plugin-backed one. Tests pass a fake.
  final PassportReader? reader;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'emrtd_core example',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
      ),
      home: ReadScreen(reader: reader ?? PassportReader()),
    );
  }
}
