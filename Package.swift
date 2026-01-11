// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "swift-openssl",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1)
    ],
    products: [
        // WARNING: These APIs should not be considered stable and may change at any time.
        .library(name: "libcrypto", targets: ["libcrypto"]),
        .library(name: "libssl", targets: ["libssl"]),
        .library(name: "OpenSSL", targets: ["OpenSSL"])
    ],
    dependencies: [
        // Dependencies used for package development
        .package(url: "https://github.com/21-DOT-DEV/swift-plugin-subtree.git", exact: "0.0.6")
    ],
    targets: [
        // MARK: - Main Targets

        .target(
            name: "OpenSSL",
            dependencies: ["libcrypto", "libssl"]
        ),
        .target(
            name: "libcrypto",
            cSettings: PackageDescription.CSetting.opensslSettings
        ),
        .target(
            name: "libssl",
            dependencies: ["libcrypto"],
            cSettings: PackageDescription.CSetting.opensslSettings
        ),

        // MARK: - Test Targets

        .testTarget(
            name: "OpenSSLTests",
            dependencies: ["OpenSSL"]
        )
    ],
    swiftLanguageModes: [.v6],
    cLanguageStandard: .c99
)

extension PackageDescription.CSetting {
    static let opensslSettings: [Self] = [
        .define("OPENSSL_NO_ASM"),
        .unsafeFlags(["-w"]) // Suppress warnings from vendored code
    ]
}

