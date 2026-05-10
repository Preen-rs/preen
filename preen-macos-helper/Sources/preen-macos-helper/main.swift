import Foundation
import Darwin

let writer = EventWriter()

do {
    guard let command = CommandLine.arguments.dropFirst().first else {
        writer.write(UpdateEvent("failed", message: "unsupported command"))
        exit(64)
    }

    switch command {
    case "update-app":
        let input = FileHandle.standardInput.readDataToEndOfFile()
        let request = try JSONDecoder().decode(UpdateRequest.self, from: input)
        let status = try await runUpdate(request, writer: writer, exitOnFailure: true)
        exit(status)
    case "update-app-root":
        guard let payload = CommandLine.arguments.dropFirst(2).first,
              let input = Data(base64Encoded: payload)
        else {
            writer.write(UpdateEvent("failed", message: "missing elevated update payload"))
            exit(65)
        }
        let request = try JSONDecoder().decode(UpdateRequest.self, from: input)
        let eventWriter = CommandLine.arguments.dropFirst(3).first
            .map { EventWriter(fileURL: URL(fileURLWithPath: $0)) } ?? writer
        _ = try await runUpdate(request, writer: eventWriter, exitOnFailure: false)
        exit(0)
    case "install-app-store-package":
        guard let payload = CommandLine.arguments.dropFirst(2).first,
              let input = Data(base64Encoded: payload)
        else {
            writer.write(UpdateEvent("failed", message: "missing elevated install payload"))
            exit(65)
        }
        let request = try JSONDecoder().decode(AppStoreInstallRequest.self, from: input)
        let eventWriter = CommandLine.arguments.dropFirst(3).first
            .map { EventWriter(fileURL: URL(fileURLWithPath: $0)) } ?? writer
        let appURL = try await MacAppStoreInstaller(writer: eventWriter).install(request)
        print(appURL.path)
        fflush(stdout)
        exit(0)
    default:
        writer.write(UpdateEvent("failed", message: "unsupported command"))
        exit(64)
    }
} catch {
    writer.write(UpdateEvent("failed", message: error.localizedDescription))
    exit(1)
}

private func runUpdate(_ request: UpdateRequest, writer: EventWriter, exitOnFailure: Bool) async throws -> Int32 {
    guard request.schemaVersion == 1 else {
        writer.write(UpdateEvent("failed", app: request.appName, message: "unsupported schema version"))
        return exitOnFailure ? 65 : 0
    }

    do {
        try await runAsSudoUserIfNeeded {
            try await runProviderUpdate(request, writer: writer)
        }
        return 0
    } catch {
        writer.write(UpdateEvent("failed", app: request.appName, message: error.localizedDescription))
        return exitOnFailure ? 1 : 0
    }
}

private func runProviderUpdate(_ request: UpdateRequest, writer: EventWriter) async throws {
    switch request.provider {
    case .macAppStore:
        try await MacAppStoreUpdater(writer: writer).update(request)
    case .sparkle:
        try await SparkleUpdater(writer: writer).update(request)
    default:
        throw HelperError.unavailable("provider is not handled by macOS helper")
    }
}
