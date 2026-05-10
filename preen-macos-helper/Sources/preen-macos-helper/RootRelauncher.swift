import Foundation
import Darwin

struct RootRelauncher {
    let writer: EventWriter

    func runMacAppStoreUpdate(_ request: UpdateRequest) async throws {
        let payload = try JSONEncoder().encode(request).base64EncodedString()
        guard let executable = Bundle.main.executableURL?.path else {
            throw HelperError.unavailable("failed to locate macOS update helper executable")
        }
        let environment = [
            "SUDO_UID=\(getuid())",
            "SUDO_GID=\(getgid())",
            "HOME=\(shellQuote(NSHomeDirectory()))",
            "USER=\(shellQuote(NSUserName()))",
            "LOGNAME=\(shellQuote(NSUserName()))",
        ].joined(separator: " ")
        let command = "/usr/bin/env \(environment) \(shellQuote(executable)) update-app-root \(shellQuote(payload))"
        let output = try await runProcess(
            "/usr/bin/osascript",
            arguments: [
                "-e", "on run argv",
                "-e", "do shell script (item 1 of argv) with administrator privileges",
                "-e", "end run",
                command,
            ]
        )
        writer.writeRaw(output)
    }

    private func runProcess(_ executable: String, arguments: [String]) async throws -> String {
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
            throw HelperError.unavailable("administrator approval failed: \(stderr.isEmpty ? stdout : stderr)")
        }
        return stdout
    }

    private func shellQuote(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}
