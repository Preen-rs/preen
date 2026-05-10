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

        let environment = [
            "SUDO_UID=\(getuid())",
            "SUDO_GID=\(getgid())",
            "HOME=\(shellQuote(NSHomeDirectory()))",
            "USER=\(shellQuote(NSUserName()))",
            "LOGNAME=\(shellQuote(NSUserName()))",
        ].joined(separator: " ")
        let command = "/usr/bin/env \(environment) \(shellQuote(executable)) update-app-root \(shellQuote(payload)) \(shellQuote(eventURL.path))"
        try await runProcessAndForwardEvents(
            "/usr/bin/osascript",
            arguments: [
                "-e", "on run argv",
                "-e", "do shell script (item 1 of argv) with administrator privileges",
                "-e", "end run",
                command,
            ],
            eventURL: eventURL
        )
    }

    private func runProcessAndForwardEvents(_ executable: String, arguments: [String], eventURL: URL) async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
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
            throw HelperError.unavailable("administrator approval failed: \(stderr.isEmpty ? stdout : stderr)")
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

    private func shellQuote(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}
