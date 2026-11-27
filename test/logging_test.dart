/// Unit tests for the logging seam: category strings verbatim
/// including case, rooted at `emrtd.*`; silent unless a handler attaches.
library;

import 'package:emrtd_core/src/logging.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:logging/logging.dart';

void main() {
  test('category strings are upstream OSLog categories, case verbatim', () {
    expect(passportReaderLog.fullName, 'emrtd.passportReader');
    expect(tagReaderLog.fullName, 'emrtd.tagReader');
    expect(secureMessagingLog.fullName, 'emrtd.secureMessaging');
    expect(bacLog.fullName, 'emrtd.BAC');
    expect(paceLog.fullName, 'emrtd.PACE');
    expect(chipAuthLog.fullName, 'emrtd.chipAuthentication');
  });

  test('all loggers hang off the emrtd parent', () {
    for (final log in [
      passportReaderLog,
      tagReaderLog,
      secureMessagingLog,
      bacLog,
      paceLog,
      chipAuthLog,
    ]) {
      expect(log.parent?.fullName, 'emrtd');
    }
  });

  test('records reach an attached handler with the full category name', () {
    final records = <LogRecord>[];
    final sub = Logger.root.onRecord.listen(records.add);
    addTearDown(sub.cancel);

    bacLog.info('challenge sent');

    expect(records, hasLength(1));
    expect(records.single.loggerName, 'emrtd.BAC');
    expect(records.single.message, 'challenge sent');
  });
}
