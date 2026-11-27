// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/Logging.swift @ 3bf5456 (2.3.2)

/// Logger seam over `package:logging`: one [Logger] per upstream OSLog
/// category, rooted at `emrtd.*`, category strings verbatim **including
/// case** (`BAC`/`PACE` are uppercase upstream). Matching categories keep
/// Dart traces diffable against upstream OSLog output during transcript
/// debugging.
///
/// Upstream's `openSSL` category (OpenSSL plumbing replaced; surviving slices
/// log under their consumer's category) is not ported.
///
/// Silent unless the app attaches a handler
/// (`Logger.root.onRecord.listen(...)`; per-subtree listeners additionally
/// need `hierarchicalLoggingEnabled = true`).
library;

import 'package:logging/logging.dart';

/// Upstream `Logger.passportReader`.
final Logger passportReaderLog = Logger('emrtd.passportReader');

/// Upstream `Logger.tagReader`.
final Logger tagReaderLog = Logger('emrtd.tagReader');

/// Upstream `Logger.secureMessaging`.
final Logger secureMessagingLog = Logger('emrtd.secureMessaging');

/// Upstream `Logger.bac` (category string `BAC`).
final Logger bacLog = Logger('emrtd.BAC');

/// Upstream `Logger.pace` (category string `PACE`).
final Logger paceLog = Logger('emrtd.PACE');

/// Upstream `Logger.chipAuth` (category string `chipAuthentication`).
final Logger chipAuthLog = Logger('emrtd.chipAuthentication');
