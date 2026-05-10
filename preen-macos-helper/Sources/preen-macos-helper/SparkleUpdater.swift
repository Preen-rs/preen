import Foundation
import Sparkle

@MainActor
final class SparkleUpdater: NSObject, SPUUserDriver, SPUUpdaterDelegate {
    private let writer: EventWriter
    private var continuation: CheckedContinuation<Void, Error>?
    private var updater: SPUUpdater?
    private var request: UpdateRequest?
    private var downloadedBytes: UInt64 = 0
    private var expectedBytes: UInt64 = 0

    init(writer: EventWriter) {
        self.writer = writer
    }

    func update(_ request: UpdateRequest) async throws {
        guard let bundle = Bundle(url: URL(fileURLWithPath: request.appPath)) else {
            throw HelperError.invalidRequest("failed to open app bundle")
        }
        self.request = request
        writer.write(UpdateEvent("checking", app: request.appName, message: "Starting Sparkle update"))

        updater = SPUUpdater(hostBundle: bundle, applicationBundle: bundle, userDriver: self, delegate: self)
        try updater?.start()
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            updater?.checkForUpdates()
        }
    }

    func show(_ request: SPUUpdatePermissionRequest, reply: @escaping (SUUpdatePermissionResponse) -> Void) {
        reply(SUUpdatePermissionResponse(automaticUpdateChecks: true, sendSystemProfile: false))
    }

    func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState, reply: @escaping (SPUUserUpdateChoice) -> Void) {
        writer.write(UpdateEvent("downloading", app: request?.appName, progress: 0.0, message: "Found Sparkle update", version: appcastItem.displayVersionString))
        reply(.install)
    }

    func showDownloadDidReceiveExpectedContentLength(_ expectedContentLength: UInt64) {
        expectedBytes = expectedContentLength
        downloadedBytes = 0
    }

    func showDownloadDidReceiveData(ofLength length: UInt64) {
        downloadedBytes += length
        let progress = expectedBytes > 0 ? min(Double(downloadedBytes) / Double(expectedBytes), 1.0) * 0.75 : 0.0
        writer.write(UpdateEvent("downloading", app: request?.appName, progress: progress, message: "Downloading Sparkle update"))
    }

    func showExtractionReceivedProgress(_ progress: Double) {
        writer.write(UpdateEvent("extracting", app: request?.appName, progress: 0.75 + progress * 0.20, message: "Extracting Sparkle update"))
    }

    func showInstallingUpdate(withApplicationTerminated: Bool, retryTerminatingApplication: @escaping () -> Void) {
        writer.write(UpdateEvent("installing", app: request?.appName, progress: 0.95, message: "Installing Sparkle update"))
    }

    func showUpdateInstalledAndRelaunched(_ relaunched: Bool, acknowledgement: @escaping () -> Void) {
        writer.write(UpdateEvent("completed", app: request?.appName, progress: 1.0, message: "Sparkle update installed"))
        acknowledgement()
        continuation?.resume()
        continuation = nil
    }

    func showUpdaterError(_ error: Error, acknowledgement: @escaping () -> Void) {
        writer.write(UpdateEvent("failed", app: request?.appName, message: error.localizedDescription))
        acknowledgement()
        continuation?.resume(throwing: error)
        continuation = nil
    }

    func showUpdateNotFoundWithError(_ error: Error, acknowledgement: @escaping () -> Void) {
        writer.write(UpdateEvent("skipped", app: request?.appName, message: "No Sparkle update available"))
        acknowledgement()
        continuation?.resume()
        continuation = nil
    }

    func feedURLString(for updater: SPUUpdater) -> String? {
        request?.feedUrl
    }

    func showUserInitiatedUpdateCheck(cancellation: @escaping () -> Void) {}
    func dismissUserInitiatedUpdateCheck() {}
    func showUpdateReleaseNotes(with downloadData: SPUDownloadData) {}
    func showUpdateReleaseNotesFailedToDownloadWithError(_ error: Error) {}
    func showUpdateInFocus() {}
    func showDownloadInitiated(cancellation: @escaping () -> Void) {}
    func showDownloadDidStartExtractingUpdate() {}
    func showReady(toInstallAndRelaunch reply: @escaping (SPUUserUpdateChoice) -> Void) { reply(.install) }
    func showSendingTerminationSignal() {}
    func dismissUpdateInstallation() {}
    func showCanCheck(forUpdates canCheckForUpdates: Bool) {}
}
