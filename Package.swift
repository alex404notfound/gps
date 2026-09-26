// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "GPSCore",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [.library(name: "GPSCore", targets: ["GPSCore"])],
    targets: [
        .target(name: "GPSCore", path: "App/Core"),
        .testTarget(name: "GPSCoreTests", dependencies: ["GPSCore"], path: "Tests/GPSCoreTests")
    ]
)
