/// Package identity constants.
///
/// [emrtdCoreVersion] is the single source for the sdk string a consumer
/// records against a read; it MUST match `pubspec.yaml`'s `version:` field
/// (pinned by `test/read_quirks_test.dart`; bump both together on release).
library;

/// The `emrtd_core` package version.
const String emrtdCoreVersion = '1.0.0';

/// The package identity string a consumer stamps on its own read metadata
/// (format `emrtd_core-<version>`), so a record says which reader produced it.
const String emrtdCoreSdkId = 'emrtd_core-$emrtdCoreVersion';
