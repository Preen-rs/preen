import Foundation

enum UpdateProvider: String, Codable {
    case homebrewCask = "HomebrewCask"
    case macAppStore = "MacAppStore"
    case sparkle = "Sparkle"
    case apt = "Apt"
    case dnf = "Dnf"
    case pacman = "Pacman"
    case flatpak = "Flatpak"
    case snap = "Snap"
    case unknown = "Unknown"
}

struct UpdateRequest: Codable {
    let schemaVersion: UInt
    let provider: UpdateProvider
    let appName: String
    let appPath: String
    let packageId: String
    let installedVersion: String?
    let latestVersion: String?
    let feedUrl: String?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case provider
        case appName = "app_name"
        case appPath = "app_path"
        case packageId = "package_id"
        case installedVersion = "installed_version"
        case latestVersion = "latest_version"
        case feedUrl = "feed_url"
    }
}

struct UpdateEvent: Codable {
    let event: String
    let app: String?
    let progress: Double?
    let message: String?
    let version: String?

    init(
        _ event: String,
        app: String? = nil,
        progress: Double? = nil,
        message: String? = nil,
        version: String? = nil
    ) {
        self.event = event
        self.app = app
        self.progress = progress
        self.message = message
        self.version = version
    }
}

struct EventWriter {
    private let encoder = JSONEncoder()

    func write(_ event: UpdateEvent) {
        guard let data = try? encoder.encode(event),
              let line = String(data: data, encoding: .utf8)
        else {
            return
        }
        print(line)
        fflush(stdout)
    }
}
