// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "preen-macos-helper",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "preen-macos-helper", targets: ["preen-macos-helper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.7.0"),
    ],
    targets: [
        .target(
            name: "PrivateFrameworks",
            path: "Sources/PrivateFrameworks",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "preen-macos-helper",
            dependencies: [
                "PrivateFrameworks",
                .product(name: "Sparkle", package: "Sparkle"),
            ],
            swiftSettings: [
                .unsafeFlags([
                    "-F", "/System/Library/PrivateFrameworks",
                ]),
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-F", "/System/Library/PrivateFrameworks",
                ]),
            ]
        ),
    ]
)
