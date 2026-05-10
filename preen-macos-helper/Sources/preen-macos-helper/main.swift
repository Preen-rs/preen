import Foundation

let writer = EventWriter()

do {
    guard CommandLine.arguments.dropFirst().first == "update-app" else {
        writer.write(UpdateEvent("failed", message: "unsupported command"))
        exit(64)
    }

    let input = FileHandle.standardInput.readDataToEndOfFile()
    let request = try JSONDecoder().decode(UpdateRequest.self, from: input)
    guard request.schemaVersion == 1 else {
        writer.write(UpdateEvent("failed", app: request.appName, message: "unsupported schema version"))
        exit(65)
    }

    switch request.provider {
    case .macAppStore:
        try await MacAppStoreUpdater(writer: writer).update(request)
    case .sparkle:
        try await SparkleUpdater(writer: writer).update(request)
    default:
        writer.write(UpdateEvent("failed", app: request.appName, message: "provider is not handled by macOS helper"))
        exit(66)
    }
} catch {
    writer.write(UpdateEvent("failed", message: error.localizedDescription))
    exit(1)
}
