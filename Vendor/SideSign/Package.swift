// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SideSign",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8),
        .visionOS(.v1)
    ],

    products: [
        .library(
            name: "SideSign",
            type: .static,
            targets: ["SideSign"]
        ),
    ],

    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git",    exact: "4.3.1"),

        .package(url: "https://github.com/mahee96/CodeSignKit.git", revision: "d0c67710fda9a2646b9e829cb2cf443892728371"),
        .package(url: "https://github.com/mahee96/GSACryptoKit.git", revision: "eae2590eaf17fe98ce9c76b3ec2bd42b780eb123"),
        .package(url: "https://github.com/SideStore/libdeflate", revision: "da6c7dae03b78dc71af973664575e4209786fbfe"),
        .package(path: "../AnisetteKit")
    ],

    targets: [
        .target(
            name: "SideSign",
            dependencies: [
                .product(name: "libdeflate", package: "libdeflate"),
                .product(name: "Crypto", package: "swift-crypto"),
                "AnisetteKit",
                "CodeSignKit",
                "GSACryptoKit"
            ],
            path: "Sources"
        )
    ],

    swiftLanguageModes: [.v6],
    cLanguageStandard: .gnu11
)
