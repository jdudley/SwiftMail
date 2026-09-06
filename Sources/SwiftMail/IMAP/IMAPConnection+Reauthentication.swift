import Foundation
import NIOIMAPCore

extension IMAPConnection {
    // MARK: - Queue-taking authentication entry points

    func login(username: String, password: String) async throws {
        try await commandQueue.run { [self] in
            try await self.loginBody(username: username, password: password)
        }
    }

    func authenticatePlain(username: String, password: String) async throws {
        try await commandQueue.run { [self] in
            try await self.authenticatePlainBody(username: username, password: password)
        }
    }

    func authenticateXOAUTH2(email: String, accessToken: String) async throws {
        try await commandQueue.run { [self] in
            try await self.authenticateXOAUTH2Body(email: email, accessToken: accessToken)
        }
    }

    // MARK: - Recovery inside the command queue

    /// Re-authenticates on the transport the caller just reopened, when the session it
    /// replaced had been authenticated and the server installed a way to do so.
    ///
    /// Runs inside the command queue: the caller is `executeCommandBody` or
    /// `startIdleSession`, right after `connectBody()`. Without this the first command
    /// after a peer reset went out on the fresh socket before any AUTHENTICATE (Gmail
    /// answers `BAD Unknown command`), and every caller that had checked
    /// `isAuthenticated` a moment earlier was already wrong by the time its command ran.
    /// Recovering here makes the check and the command atomic and single-flight, because
    /// the queue serializes them, and it covers IDLE, which never consulted the server's
    /// re-authentication path.
    func reauthenticateIfSessionWasLost(before operation: String) async throws {
        guard lostAuthenticatedSession, !authenticationInProgress else { return }
        guard let reauthenticate = reauthenticateAfterReconnect else {
            let warning = "\(connectionContext) Lost an authenticated session with no re-authentication "
                + "configured; \(operation) runs unauthenticated"
            logger.warning("\(warning)")
            return
        }
        logger.info("\(connectionContext) Re-authenticating the reopened transport before \(operation)")
        try await reauthenticate(self)
    }

    /// LOGIN for a caller that already holds the command queue.
    func loginBody(username: String, password: String) async throws {
        authenticationInProgress = true
        defer { authenticationInProgress = false }
        let command = LoginCommand(username: username, password: password)
        let loginCapabilities = try await executeCommandBody(command)
        markSessionAuthenticated()
        try await refreshCapabilities(using: loginCapabilities, useCommandBody: true)
        await fetchNamespacesIfSupported(useCommandBody: true)
    }

    /// ID for a caller that already holds the command queue.
    func idBody(_ identification: Identification) async throws -> Identification {
        guard capabilities.contains(.id) else {
            throw IMAPError.commandNotSupported("ID command not supported by server")
        }
        return try await executeCommandBody(IDCommand(identification: identification))
    }

    /// Every successful authentication lands here: the session is live again and no
    /// longer counts as lost.
    func markSessionAuthenticated() {
        isSessionAuthenticated = true
        lostAuthenticatedSession = false
    }
}
