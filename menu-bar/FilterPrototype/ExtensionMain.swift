import Foundation
import NetworkExtension

// System-extension entry point. The host app and authorized provisioning are
// required to activate this executable; this source is never run by the build.
@main
enum ExtensionMain {
    static func main() {
        NEProvider.startSystemExtensionMode()
        dispatchMain()
    }
}
