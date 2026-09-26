#!/usr/bin/env swift
// Original vector artwork for this reconstruction. Regenerate from the repository root.
import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

let size = 1024
let space = CGColorSpaceCreateDeviceRGB()
let canvas = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8,
                       bytesPerRow: 0, space: space, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
let colors = [CGColor(red: 0.02, green: 0.17, blue: 0.55, alpha: 1),
              CGColor(red: 0.04, green: 0.49, blue: 0.98, alpha: 1)] as CFArray
let gradient = CGGradient(colorsSpace: space, colors: colors, locations: [0, 1])!
canvas.drawLinearGradient(gradient, start: CGPoint(x: 0, y: 0),
                          end: CGPoint(x: 1024, y: 1024), options: [])
canvas.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.13))
canvas.setLineWidth(7)
for radius in [360.0, 253.0] {
    canvas.strokeEllipse(in: CGRect(x: 512 - radius, y: 512 - radius,
                                   width: radius * 2, height: radius * 2))
}
canvas.setLineCap(.round)
canvas.setLineWidth(10)
for angle in [0.0, Double.pi / 2, Double.pi, Double.pi * 1.5] {
    canvas.move(to: CGPoint(x: 512 + cos(angle) * 334, y: 512 + sin(angle) * 334))
    canvas.addLine(to: CGPoint(x: 512 + cos(angle) * 387, y: 512 + sin(angle) * 387))
    canvas.strokePath()
}
let arrow = CGMutablePath()
arrow.move(to: CGPoint(x: 758, y: 773))
arrow.addLine(to: CGPoint(x: 576, y: 257))
arrow.addLine(to: CGPoint(x: 467, y: 492))
arrow.addLine(to: CGPoint(x: 245, y: 598))
arrow.closeSubpath()
canvas.setShadow(offset: CGSize(width: 0, height: -14), blur: 38,
                 color: CGColor(red: 0, green: 0.07, blue: 0.25, alpha: 0.25))
canvas.setFillColor(CGColor(gray: 1, alpha: 1))
canvas.addPath(arrow)
canvas.fillPath()

let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let assets = root.appendingPathComponent("App/Resources/Assets.xcassets")
let output = assets.appendingPathComponent("AppIcon.appiconset")
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
let imageURL = output.appendingPathComponent("AppIcon.png")
let destination = CGImageDestinationCreateWithURL(imageURL as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(destination, canvas.makeImage()!, nil)
guard CGImageDestinationFinalize(destination) else { fatalError("Could not write icon") }
let info: [String: Any] = ["author": "xcode", "version": 1]
let catalog: [String: Any] = ["images": [["filename": "AppIcon.png", "idiom": "universal", "platform": "ios", "size": "1024x1024"]], "info": info]
try JSONSerialization.data(withJSONObject: catalog, options: [.prettyPrinted, .sortedKeys])
    .write(to: output.appendingPathComponent("Contents.json"))
try JSONSerialization.data(withJSONObject: ["info": info], options: [.prettyPrinted, .sortedKeys])
    .write(to: assets.appendingPathComponent("Contents.json"))
print("Generated AppIcon.png and asset catalog")
