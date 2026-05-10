import CoreServices
import Darwin
import Foundation

#if canImport(CommerceKit) && canImport(StoreFoundation)
import CommerceKit
import StoreFoundation
#endif

struct MacAppStoreUpdater {
    let writer: EventWriter

    func update(_ request: UpdateRequest) async throws {
        writer.write(UpdateEvent("checking", app: request.appName, message: "Starting Mac App Store update"))
        guard !request.packageId.isEmpty else {
            throw HelperError.invalidRequest("missing App Store Adam ID")
        }

        #if canImport(CommerceKit) && canImport(StoreFoundation)
        try await performStorePurchase(request)
        #else
        throw HelperError.unavailable("CommerceKit/StoreFoundation are unavailable in this helper build")
        #endif
    }

    #if canImport(CommerceKit) && canImport(StoreFoundation)
    private func performStorePurchase(_ request: UpdateRequest) async throws {
        writer.write(UpdateEvent("downloading", app: request.appName, progress: 0.05, message: "Requesting App Store download"))
        guard let adamId = UInt64(request.packageId) else {
            throw HelperError.invalidRequest("App Store Adam ID is invalid")
        }

        let purchase = SSPurchase(
            buyParameters: "productType=C&price=0&pg=default&appExtVrsId=0&pricingParameters=STDRDL&salableAdamId=\(request.packageId)"
        )
        purchase.isRedownload = true
        purchase.isUpdate = true
        purchase.itemIdentifier = adamId

        let metadata = SSDownloadMetadata(kind: "software")
        metadata.itemIdentifier = adamId
        purchase.downloadMetadata = metadata

        let queue = CKDownloadQueue.shared()
        let observer = MacAppStoreDownloadObserver(request: request, adamId: adamId, writer: writer)
        let observerToken = queue.add(observer)
        defer { queue.removeObserver(observerToken) }

        try await withCheckedThrowingContinuation { continuation in
            observer.setContinuation(continuation)
            CKPurchaseController.shared().perform(purchase, withOptions: 0) { _, _, error, response in
                if let error {
                    observer.finish(throwing: error)
                    return
                }
                guard response?.downloads?.isEmpty == false else {
                    observer.finish(throwing: HelperError.unavailable("App Store did not start a download"))
                    return
                }
            }
        }
    }
    #endif
}

#if canImport(CommerceKit) && canImport(StoreFoundation)
private final class MacAppStoreDownloadObserver: NSObject, CKDownloadQueueObserver, @unchecked Sendable {
    private let request: UpdateRequest
    private let adamId: UInt64
    private let writer: EventWriter
    private let lock = NSLock()
    private let downloadFolderURL: URL
    private var continuation: CheckedContinuation<Void, Error>?
    private var finished = false
    private var lastEventKey: String?
    private var pkgHardLinkURL: URL?
    private var receiptHardLinkURL: URL?
    private var fallbackStarted = false

    init(request: UpdateRequest, adamId: UInt64, writer: EventWriter) {
        self.request = request
        self.adamId = adamId
        self.writer = writer
        self.downloadFolderURL = URL(fileURLWithPath: "\(CKDownloadDirectory(nil))/\(adamId)", isDirectory: true)
    }

    func setContinuation(_ continuation: CheckedContinuation<Void, Error>) {
        lock.lock()
        self.continuation = continuation
        lock.unlock()
    }

    func downloadQueue(_ queue: CKDownloadQueue, changedWithAddition download: SSDownload) {
        guard matches(download) else { return }
        writer.write(UpdateEvent("downloading", app: request.appName, progress: 0.05, message: "App Store download queued"))
    }

    func downloadQueue(_ queue: CKDownloadQueue, statusChangedFor download: SSDownload) {
        guard matches(download), let status = download.status else { return }
        refreshDownloadArtifacts()

        let phase = phaseName(status.activePhase?.phaseType)
        let progress = Double(max(status.percentComplete, status.phasePercentComplete))
        writeProgressEvent(phase.event, progress: progress, message: phase.message)

        if status.isFailed {
            let error = status.error
            if isInstallerStartFailure(error) {
                if beginInstallerFallback() {
                    Task {
                        await installDownloadedPackageAfterStoreAgentFailure(originalError: error)
                    }
                }
            } else {
                finish(throwing: error ?? HelperError.unavailable("App Store download failed"))
            }
            return
        }
        if status.isCancelled {
            finish(throwing: HelperError.unavailable("App Store download was cancelled"))
        }
    }

    func downloadQueue(_ queue: CKDownloadQueue, changedWithRemoval download: SSDownload) {
        guard matches(download) else { return }
        if download.status?.isFailed == true {
            let error = download.status?.error
            if isInstallerStartFailure(error) {
                if beginInstallerFallback() {
                    Task {
                        await installDownloadedPackageAfterStoreAgentFailure(originalError: error)
                    }
                }
            } else {
                finish(throwing: error ?? HelperError.unavailable("App Store download failed"))
            }
            return
        }
        writer.write(UpdateEvent("completed", app: request.appName, progress: 1.0, message: "App Store update installed"))
        finish()
    }

    private func matches(_ download: SSDownload) -> Bool {
        guard let metadata = download.metadata else { return false }
        return metadata.itemIdentifier == adamId
    }

    private func writeProgressEvent(_ event: String, progress: Double, message: String) {
        let roundedProgress = (progress * 100).rounded() / 100
        let key = "\(event):\(roundedProgress):\(message)"
        lock.lock()
        let shouldWrite = key != lastEventKey
        if shouldWrite {
            lastEventKey = key
        }
        lock.unlock()
        guard shouldWrite else { return }
        writer.write(UpdateEvent(event, app: request.appName, progress: roundedProgress, message: message))
    }

    private func refreshDownloadArtifacts() {
        do {
            guard FileManager.default.fileExists(atPath: downloadFolderURL.path) else {
                return
            }
            let urls = try FileManager.default.contentsOfDirectory(
                at: downloadFolderURL,
                includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey]
            )
            if let pkgURL = try urls
                .compactMap({ url -> (url: URL, date: Date)? in
                    guard url.pathExtension == "pkg" else { return nil }
                    let values = try url.resourceValues(forKeys: [.contentModificationDateKey, .isRegularFileKey])
                    guard values.isRegularFile == true, let date = values.contentModificationDate else { return nil }
                    return (url, date)
                })
                .max(by: { $0.date < $1.date })?
                .url
            {
                pkgHardLinkURL = try hardLinkURL(to: pkgURL, existing: pkgHardLinkURL)
            }
            if let receiptURL = urls.first(where: { $0.lastPathComponent == "receipt" }) {
                receiptHardLinkURL = try hardLinkURL(to: receiptURL, existing: receiptHardLinkURL)
            }
        } catch {
            // Keep artifact probing quiet during normal progress callbacks. If fallback needs
            // these files and they are missing, installDownloadedPackage() reports that clearly.
        }
    }

    private func hardLinkURL(to url: URL, existing: URL?) throws -> URL {
        if let existing, try linksToSameInode(url, existing) {
            return existing
        }
        let hardLinkDir = try FileManager.default.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: url,
            create: true
        )
        let hardLinkURL = hardLinkDir.appendingPathComponent("\(adamId)-\(url.lastPathComponent)")
        try FileManager.default.linkItem(at: url, to: hardLinkURL)
        return hardLinkURL
    }

    private func linksToSameInode(_ lhs: URL, _ rhs: URL) throws -> Bool {
        let lhsId = try lhs.resourceValues(forKeys: [.fileResourceIdentifierKey]).fileResourceIdentifier
        let rhsId = try rhs.resourceValues(forKeys: [.fileResourceIdentifierKey]).fileResourceIdentifier
        return lhsId != nil && lhsId?.isEqual(rhsId) == true
    }

    private func isInstallerStartFailure(_ error: Error?) -> Bool {
        guard let error = error as NSError? else { return false }
        return error.domain == "PKInstallErrorDomain" && error.code == 201
    }

    private func beginInstallerFallback() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !finished, !fallbackStarted else { return false }
        fallbackStarted = true
        return true
    }

    private func installDownloadedPackageAfterStoreAgentFailure(originalError: Error?) async {
        do {
            let appURL = try await installDownloadedPackage()
            writer.write(UpdateEvent("completed", app: request.appName, progress: 1.0, message: "App Store update installed in \(appURL.path)"))
            finish()
        } catch {
            let original = originalError.map { " StoreAgent error: \($0.localizedDescription)." } ?? ""
            finish(throwing: HelperError.unavailable("App Store installer workaround failed.\(original) \(error.localizedDescription)"))
        }
    }

    private func installDownloadedPackage() async throws -> URL {
        guard let pkgHardLinkURL else {
            throw HelperError.unavailable("downloaded App Store package was not found")
        }
        guard let receiptHardLinkURL else {
            throw HelperError.unavailable("downloaded App Store receipt was not found")
        }
        guard geteuid() == 0 else {
            throw HelperError.unavailable("administrator approval is required to install the downloaded App Store package")
        }

        writeProgressEvent("installing", progress: 0.92, message: "Installing downloaded App Store package")
        let installerResult = try await runProcess(
            "/usr/sbin/installer",
            arguments: ["-dumplog", "-pkg", pkgHardLinkURL.path, "-target", "/"]
        )
        let installerOutput = [installerResult.0, installerResult.1]
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
        guard let appURL = appFolderURL(fromInstallerOutput: installerOutput) else {
            throw HelperError.unavailable("installer finished but app bundle path was not reported: \(installerOutput)")
        }

        let receiptURL = appURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("_MASReceipt", isDirectory: true)
            .appendingPathComponent("receipt")
        try copyReceipt(from: receiptHardLinkURL, to: receiptURL)

        _ = try? await runProcess("/usr/bin/mdimport", arguments: [appURL.path])
        LSRegisterURL(appURL as CFURL, true)
        return appURL
    }

    private func copyReceipt(from sourceURL: URL, to receiptURL: URL) throws {
        let fileManager = FileManager.default
        let receiptDirectoryURL = receiptURL.deletingLastPathComponent()
        if !fileManager.fileExists(atPath: receiptDirectoryURL.path) {
            try fileManager.createDirectory(
                at: receiptDirectoryURL,
                withIntermediateDirectories: true,
                attributes: [.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755]
            )
        }
        if fileManager.fileExists(atPath: receiptURL.path) {
            try fileManager.removeItem(at: receiptURL)
        }
        try fileManager.copyItem(at: sourceURL, to: receiptURL)
        try fileManager.setAttributes(
            [.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755],
            ofItemAtPath: receiptURL.path
        )
    }

    private func appFolderURL(fromInstallerOutput output: String) -> URL? {
        let pattern = #"PackageKit: Registered bundle (\S+) for uid 0"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(output.startIndex..<output.endIndex, in: output)
        let matches = regex.matches(in: output, range: range)
        return matches
            .compactMap { match -> URL? in
                guard let capture = Range(match.range(at: 1), in: output) else { return nil }
                return URL(string: String(output[capture]))
            }
            .min(by: { $0.path.count < $1.path.count })
    }

    private func runProcess(_ executable: String, arguments: [String]) async throws -> (String, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        try process.run()
        process.waitUntilExit()
        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            let output = [stderr, stdout].filter { !$0.isEmpty }.joined(separator: "\n")
            throw HelperError.unavailable("\(executable) exited with \(process.terminationStatus): \(output)")
        }
        return (stdout, stderr)
    }

    private func phaseName(_ phaseType: Int64?) -> (event: String, message: String) {
        switch phaseType {
        case 0:
            return ("downloading", "Downloading App Store update")
        case 1:
            return ("installing", "Installing App Store update")
        case 5:
            return ("downloaded", "Downloaded App Store update")
        default:
            return ("processing", "Processing App Store update")
        }
    }

    func finish(throwing error: Error? = nil) {
        lock.lock()
        defer { lock.unlock() }
        guard !finished, let continuation else { return }
        finished = true
        self.continuation = nil
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume()
        }
    }
}
#endif

enum HelperError: LocalizedError {
    case invalidRequest(String)
    case unavailable(String)

    var errorDescription: String? {
        switch self {
        case .invalidRequest(let message), .unavailable(let message):
            message
        }
    }
}
