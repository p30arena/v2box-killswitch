// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "V2BoxGuardPreview",
    platforms: [.macOS(.v12)],
    products: [.executable(name: "V2BoxGuardPreview", targets: ["V2BoxGuardPreview"])],
    targets: [.executableTarget(name: "V2BoxGuardPreview")]
)
