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
        .package(url: "https://github.com/21-DOT-DEV/swift-plugin-subtree.git", exact: "0.0.7")
    ],
    targets: [
        // MARK: - Main Targets

        .target(
            name: "OpenSSL",
            dependencies: ["libcrypto", "libssl"]
        ),
        .target(
            name: "libcrypto",
            exclude: [
                "src/crypto/LPdir_unix.c",      // #included by o_dir.c (line 28), not compiled separately
                "src/crypto/des/ncbc_enc.c",    // #included by cbc_enc.c
             ],
             cSettings: [
                .headerSearchPath("include"),                  // For <openssl/xxx.h> (public headers)
                .headerSearchPath("internal_include/include"), // For "crypto/xxx.h" and "internal/xxx.h"
                .headerSearchPath("internal_include"),          // For "include/crypto/xxx.h" (provider includes)
                .headerSearchPath("src"),                      // For "crypto/xxx/xxx_local.h" local headers
                .headerSearchPath("providers/providers/common/include"), // For "prov/xxx.h" provider headers
                .headerSearchPath("providers/providers/implementations/include"), // For provider implementation headers
                .headerSearchPath("providers/providers/fips/include"), // For "fips/fipsindicator.h"
                // SPM-specific path overrides (runtime paths for config/engines/modules)
                .define("OPENSSLDIR", to: "\"/usr/local/ssl\""),
                .define("ENGINESDIR", to: "\"/usr/local/lib/engines\""),
                .define("MODULESDIR", to: "\"/usr/local/lib/ossl-modules\""),
                // Note: Algorithm disables (OPENSSL_NO_*) are in configuration.h via ./Configure options
                // See README.md "Regenerating Configure-Generated Files" for the full list
             ]
        ),
        .target(
            name: "libssl",
            dependencies: ["libcrypto"],
            cSettings: [
                .headerSearchPath("../libcrypto/include"),
                .headerSearchPath("../libcrypto/internal_include/include"),
                .headerSearchPath("ssl"),  // For local ssl includes
                // Build configuration (matches: ./Configure darwin64-arm64-cc no-asm no-shared)
                .define("OPENSSL_NO_ASM"),
                .define("OPENSSL_PIC"),
             ]
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