import Foundation
import Darwin

// Fixture ONLY: launchd starts this as a bundled PER-USER XPC service after
// an explicitly approved diagnostic run. No root, PF, VPN, protected writes or arbitrary RPC.
// The watchdog exits this fixture process itself; it never signals another PID.
if #available(macOS 13.0, *) {
    guard geteuid() != 0 else { exit(1) }
    DispatchQueue.global().asyncAfter(deadline: .now() + 15) { exit(0) }
    do {
        let config = try FixtureConfig()
        guard config.parentStillMatches() else { throw FixtureFailure.unavailable }
        let core = try RecoveryEndpointHandoff(ticket: config.ticket, callerUID: geteuid(),
            callerPID: config.parentPID, pin: config.pin("parent_hash"),
            validateLaunch: { config.parentStillMatches() }, lifetime: 8)
        let delegate = core.delegate()
        let listener = NSXPCListener.service()
        listener.delegate = delegate
        withExtendedLifetime(core) {
            withExtendedLifetime(delegate) { listener.resume() }
        }
    } catch {
        fputs("Read-only XPC fixture refused startup.\n", stderr)
        exit(1)
    }
} else { exit(1) }
