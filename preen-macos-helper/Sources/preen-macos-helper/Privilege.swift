import Darwin
import Foundation

struct EffectiveIdentity {
    let uid: uid_t
    let gid: gid_t
}

func sudoIdentity() -> EffectiveIdentity? {
    let environment = ProcessInfo.processInfo.environment
    guard let uidText = environment["SUDO_UID"],
          let gidText = environment["SUDO_GID"],
          let uid = uid_t(uidText),
          let gid = gid_t(gidText)
    else {
        return nil
    }
    return EffectiveIdentity(uid: uid, gid: gid)
}

func runAsSudoUserIfNeeded<T>(_ body: () async throws -> T) async throws -> T {
    guard geteuid() == 0, let identity = sudoIdentity() else {
        return try await body()
    }
    return try await withEffectiveIdentity(identity, body)
}

func runAsRoot<T>(_ body: () async throws -> T) async throws -> T {
    try await withEffectiveIdentity(EffectiveIdentity(uid: 0, gid: 0), body)
}

private func withEffectiveIdentity<T>(_ identity: EffectiveIdentity, _ body: () async throws -> T) async throws -> T {
    let originalUID = geteuid()
    let originalGID = getegid()
    if originalUID == 0 {
        try setEffectiveGID(identity.gid)
        defer { try? setEffectiveGID(originalGID) }
        try setEffectiveUID(identity.uid)
        defer { try? setEffectiveUID(originalUID) }
        return try await body()
    }

    try setEffectiveUID(identity.uid)
    defer { try? setEffectiveUID(originalUID) }
    try setEffectiveGID(identity.gid)
    defer { try? setEffectiveGID(originalGID) }
    return try await body()
}

private func setEffectiveUID(_ uid: uid_t) throws {
    guard seteuid(uid) == 0 else {
        throw HelperError.unavailable("failed to switch effective user to \(uid): \(String(cString: strerror(errno)))")
    }
}

private func setEffectiveGID(_ gid: gid_t) throws {
    guard setegid(gid) == 0 else {
        throw HelperError.unavailable("failed to switch effective group to \(gid): \(String(cString: strerror(errno)))")
    }
}
