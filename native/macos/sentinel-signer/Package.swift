// swift-tools-version:5.9
// sentinel-signer: the signing-device (SD) application, protocol v1 (D-45..D-47, D-73).
// Built and reviewed ON the signing device (signing-device design §7). No third-party dependencies.
import PackageDescription

let package = Package(
    name: "sentinel-signer",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "sentinel-signer", targets: ["sentinel-signer"]),
    ],
    targets: [
        .target(name: "SignerCore", path: "Sources/SignerCore"),
        .executableTarget(name: "sentinel-signer", dependencies: ["SignerCore"], path: "Sources/sentinel-signer"),
        // TEST-ONLY: drives SignerCore with a disposable software key so the DM side can be tested for
        // interoperability. It is never built into or shipped with the signer product.
        .executableTarget(name: "signer-interop", dependencies: ["SignerCore"], path: "Sources/signer-interop"),
        .testTarget(name: "SignerCoreTests", dependencies: ["SignerCore"], path: "Tests/SignerCoreTests"),
    ]
)
