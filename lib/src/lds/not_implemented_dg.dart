// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/NotImplementedDG.swift @ 3bf5456 (2.3.2)

/// `NotImplementedDG`: the trivial base-walk-only subclass.
///
/// The tags dispatching here are exactly the ones **upstream also has no
/// parser for** (DG3/4/5/6/8/9/10/13/16), so a read of any unparsed DG still
/// yields usable `body`/`data` bytes the SOD hash oracle can check. The
/// upstream `NotImplemented` error case is dropped: upstream never throws
/// it.
library;

import 'data_group.dart';
import 'data_group_id.dart';

/// Upstream `NotImplementedDG`.
class NotImplementedDG extends DataGroup {
  NotImplementedDG(super.data);

  @override
  DataGroupId get datagroupType => DataGroupId.Unknown;
}
