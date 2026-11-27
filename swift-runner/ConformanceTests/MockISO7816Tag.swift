// Mock ISO7816 tag (Swift side).
//
// A scripted NFCISO7816Tag: TagReader's only transport dependency is this
// protocol, so replaying golden transcripts against the *unmodified*
// upstream TagReader needs nothing but this mock (no seams). Each step
// optionally carries an expected structured command (CLA/INS/P1/P2/data/Le:
// the cross-runner comparable surface; wire bytes are a
// Dart-runner-only assertion) and a canned response. First compiled at
// rented-Mac session S2.

import CoreNFC
import Foundation

/// The `le` a conformance fixture compares against. CoreNFC reports
/// `expectedResponseLength` 0 for a case-4 short APDU whose Le byte is `00`
/// (the shape of upstream's short secure-messaging wrapper), where ISO 7816-4
/// and the fixtures mean 256; the struct initializer never produces 0 on a
/// shared path. Verified on iOS 26.3.1.
func conformanceLe(_ apdu: NFCISO7816APDU) -> Int {
    apdu.expectedResponseLength == 0 ? 256 : apdu.expectedResponseLength
}

final class MockISO7816Tag: NSObject, NFCISO7816Tag {

    struct ExpectedCommand {
        let cla: UInt8
        let ins: UInt8
        let p1: UInt8
        let p2: UInt8
        let data: [UInt8]
        /// SCHEMA.md le semantics (-1 = absent); compared through conformanceLe
        let le: Int
    }

    struct Step {
        /// nil = canned mode (no command assertion, used by the
        /// apdu.response vector op; transcripts always assert).
        let expected: ExpectedCommand?
        let respData: Data
        let sw1: UInt8
        let sw2: UInt8
    }

    private let steps: [Step]
    /// Forwarded to XCTFail by the caller (kept out of this file so the
    /// mock itself has no XCTest dependency).
    private let onMismatch: (String) -> Void

    private(set) var consumed = 0
    /// Every command the implementation sent, in order (commandBuild ops).
    private(set) var received: [NFCISO7816APDU] = []

    var exhausted: Bool { consumed == steps.count }

    init(steps: [Step], onMismatch: @escaping (String) -> Void) {
        self.steps = steps
        self.onMismatch = onMismatch
        super.init()
    }

    // MARK: - scripted transceive

    func sendCommand(
        apdu: NFCISO7816APDU,
        completionHandler: @escaping (Data, UInt8, UInt8, Error?) -> Void
    ) {
        received.append(apdu)
        guard consumed < steps.count else {
            onMismatch(
                "mock tag exhausted after \(consumed) step(s); "
                    + "unexpected command ins=\(String(format: "%02x", apdu.instructionCode))")
            completionHandler(Data(), 0x6F, 0x00, nil)
            return
        }
        let step = steps[consumed]
        let stepLabel = "step \(consumed + 1)"
        consumed += 1

        if let expected = step.expected {
            let mismatches = [
                ("cla", Int(apdu.instructionClass), Int(expected.cla)),
                ("ins", Int(apdu.instructionCode), Int(expected.ins)),
                ("p1", Int(apdu.p1Parameter), Int(expected.p1)),
                ("p2", Int(apdu.p2Parameter), Int(expected.p2)),
                ("le", conformanceLe(apdu), expected.le),
            ].filter { $0.1 != $0.2 }
            for (field, got, want) in mismatches {
                onMismatch("\(stepLabel): \(field) mismatch; got \(got), expected \(want)")
            }
            let gotData = [UInt8](apdu.data ?? Data())
            if gotData != expected.data {
                let gotHex: String = gotData.map { String(format: "%02x", $0) }.joined()
                let wantHex: String = expected.data.map { String(format: "%02x", $0) }.joined()
                onMismatch("\(stepLabel): data mismatch; got \(gotHex), expected \(wantHex)")
            }
        }
        completionHandler(step.respData, step.sw1, step.sw2, nil)
    }

    // MARK: - inert NFCISO7816Tag surface

    var initialSelectedAID: String { "A0000002471001" }
    var identifier: Data { Data([0x08, 0x15]) }
    var historicalBytes: Data? { nil }
    var applicationData: Data? { nil }
    var proprietaryApplicationDataCoding: Bool { false }

    // MARK: - inert NFCTag plumbing

    var type: __NFCTagType { .iso7816Compatible }
    var session: NFCReaderSessionProtocol? { nil }
    var isAvailable: Bool { true }

    func asNFCISO15693Tag() -> NFCISO15693Tag? { nil }
    func asNFCISO7816Tag() -> NFCISO7816Tag? { self }
    func asNFCFeliCaTag() -> NFCFeliCaTag? { nil }
    func asNFCMiFareTag() -> NFCMiFareTag? { nil }

    // MARK: - inert NFCNDEFTag surface (inherited by NFCISO7816Tag; never
    // called by upstream's eMRTD read path)

    func queryNDEFStatus(
        completionHandler: @escaping (NFCNDEFStatus, Int, Error?) -> Void
    ) {
        completionHandler(.notSupported, 0, NFCReaderError(.readerErrorUnsupportedFeature))
    }

    func readNDEF(completionHandler: @escaping (NFCNDEFMessage?, Error?) -> Void) {
        completionHandler(nil, NFCReaderError(.readerErrorUnsupportedFeature))
    }

    func writeNDEF(
        _ ndefMessage: NFCNDEFMessage, completionHandler: @escaping (Error?) -> Void
    ) {
        completionHandler(NFCReaderError(.readerErrorUnsupportedFeature))
    }

    func writeLock(completionHandler: @escaping (Error?) -> Void) {
        completionHandler(NFCReaderError(.readerErrorUnsupportedFeature))
    }

    func copy(with zone: NSZone? = nil) -> Any { self }

    static var supportsSecureCoding: Bool { true }
    func encode(with coder: NSCoder) {}
    required init?(coder: NSCoder) { return nil }
}
