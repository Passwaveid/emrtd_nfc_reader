# src/transport

The NFC transport: the `NfcTransceiver` and `NfcSession` interfaces the rest
of the package talks to, and their `flutter_nfc_kit` implementations. **This
is the only directory allowed to import Flutter or plugin APIs**, and only
`nfc_kit_transceiver.dart` does, so a later split into a pure-Dart core
package stays a mechanical move.

`poll` passes on the plugin's real `maxTransceiveLength` and
`isExtendedLengthApduSupported`, fields that only the fork under
`vendor/flutter_nfc_kit` has (see its `VENDORING.md`), and the transceiver
exposes the tag's `historicalBytes`. Its `tagCapabilities` getter returns a
`TagCapabilities`: the poll response's tag type, standard, ATQA/SAK and ATQB
fields as the plugin reports them, with the tag identifier left out on
purpose. Every `NfcTransceiver` implementation must answer it, and `null` is
the right answer for a transport with no polled tag.
