import Foundation
import Darwin

struct RootRelauncher {
    let writer: EventWriter
    private let timeoutSeconds: TimeInterval = 10 * 60
    private let idleTimeoutSeconds: TimeInterval = 180

    func runMacAppStoreUpdate(_ request: UpdateRequest) async throws {
        let payload = try JSONEncoder().encode(request).base64EncodedString()
        guard let executable = Bundle.main.executableURL?.path else {
            throw HelperError.unavailable("failed to locate macOS update helper executable")
        }
        let eventURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("preen-app-store-update-\(UUID().uuidString).jsonl")
        FileManager.default.createFile(atPath: eventURL.path, contents: nil)
        defer { try? FileManager.default.removeItem(at: eventURL) }

        let askpassURL = try createAskpassScript()
        defer { try? FileManager.default.removeItem(at: askpassURL) }

        try await runProcessAndForwardEvents(
            "/usr/bin/sudo",
            arguments: [
                "-A",
                executable,
                "update-app-root",
                payload,
                eventURL.path,
            ],
            eventURL: eventURL,
            environment: [
                "SUDO_ASKPASS": askpassURL.path,
                "SUDO_PROMPT": "Preen needs administrator approval to update \(request.appName)",
            ]
        )
    }

    private func createAskpassScript() throws -> URL {
        let askpassURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("preen-askpass-\(UUID().uuidString).sh")
        let script = """
        #!/bin/sh
        /usr/bin/osascript -e 'on run argv' -e 'display dialog (item 1 of argv) default answer "" with hidden answer buttons {"OK", "Cancel"} default button "OK" cancel button "Cancel"' -e 'text returned of result' -e 'end run' "$1"
        """
        try script.write(to: askpassURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: askpassURL.path
        )
        return askpassURL
    }

    private func runProcessAndForwardEvents(
        _ executable: String,
        arguments: [String],
        eventURL: URL,
        environment: [String: String]
    ) async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        try process.run()

        var forwardedBytes = 0
        var lastEventAt = Date()
        let startedAt = Date()
        while process.isRunning {
            let didForward = forwardNewEvents(from: eventURL, offset: &forwardedBytes)
            if didForward {
                lastEventAt = Date()
            } else if Date().timeIntervalSince(lastEventAt) > idleTimeoutSeconds {
                process.terminate()
                throw HelperError.unavailable("Mac App Store update helper did not report progress after administrator approval")
            } else if Date().timeIntervalSince(startedAt) > timeoutSeconds {
                process.terminate()
                throw HelperError.unavailable("Mac App Store update helper timed out")
            }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        _ = forwardNewEvents(from: eventURL, offset: &forwardedBytes)

        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            let output = [stderr, stdout].filter { !$0.isEmpty }.joined(separator: "\n")
            throw HelperError.unavailable("Mac App Store update helper failed: \(output)")
        }
        writer.writeRaw(stdout)
    }

    private func forwardNewEvents(from eventURL: URL, offset: inout Int) -> Bool {
        guard let data = try? Data(contentsOf: eventURL), data.count > offset else {
            return false
        }
        let chunk = data.subdata(in: offset..<data.count)
        offset = data.count
        guard let text = String(data: chunk, encoding: .utf8), !text.isEmpty else {
            return false
        }
        writer.writeRaw(text)
        return true
    }

}
