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
    private var continuation: CheckedContinuation<Void, Error>?
    private var finished = false

    init(request: UpdateRequest, adamId: UInt64, writer: EventWriter) {
        self.request = request
        self.adamId = adamId
        self.writer = writer
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
        if status.isCancelled {
            finish(throwing: HelperError.unavailable("App Store download was cancelled"))
            return
        }
        if status.isFailed {
            finish(throwing: status.error ?? HelperError.unavailable("App Store download failed"))
            return
        }

        let phase = phaseName(status.activePhase?.phaseType)
        let progress = Double(max(status.percentComplete, status.phasePercentComplete))
        writer.write(UpdateEvent(phase.event, app: request.appName, progress: progress, message: phase.message))
    }

    func downloadQueue(_ queue: CKDownloadQueue, changedWithRemoval download: SSDownload) {
        guard matches(download) else { return }
        if download.status?.isFailed == true {
            finish(throwing: download.status?.error ?? HelperError.unavailable("App Store download failed"))
            return
        }
        writer.write(UpdateEvent("completed", app: request.appName, progress: 1.0, message: "App Store update installed"))
        finish()
    }

    private func matches(_ download: SSDownload) -> Bool {
        guard let metadata = download.metadata else { return false }
        return metadata.itemIdentifier == adamId
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
