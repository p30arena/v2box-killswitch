import Foundation

// Shared by client and helper: no arbitrary commands, paths, config or PF text.
@objc protocol GuardXPCProtocol {
    func status(_ reply: @escaping (Data?, String?) -> Void)
    func checkAuthorization(_ authorization: Data, reply: @escaping (Data?, String?) -> Void)
    func setProtectionEnabled(_ enabled: Bool, authorization: Data,
                              reply: @escaping (Data?, String?) -> Void)
    func reconnectVPN(_ reply: @escaping (Data?, String?) -> Void)
}
