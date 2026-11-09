import AppKit
import CoreGraphics

let size = 1024
let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8,
                    bytesPerRow: size * 4, space: CGColorSpaceCreateDeviceRGB(),
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
let tile = CGPath(roundedRect: CGRect(x: 82, y: 82, width: 860, height: 860), cornerWidth: 185, cornerHeight: 185, transform: nil)
ctx.setFillColor(CGColor(red: 0.09, green: 0.16, blue: 0.29, alpha: 1))
ctx.addPath(tile)
ctx.fillPath()
let shield = CGMutablePath()
shield.move(to: CGPoint(x: 512, y: 795))
shield.addQuadCurve(to: CGPoint(x: 742, y: 708), control: CGPoint(x: 626, y: 741))
shield.addQuadCurve(to: CGPoint(x: 512, y: 242), control: CGPoint(x: 735, y: 392))
shield.addQuadCurve(to: CGPoint(x: 282, y: 708), control: CGPoint(x: 289, y: 392))
shield.addQuadCurve(to: CGPoint(x: 512, y: 795), control: CGPoint(x: 398, y: 741))
shield.closeSubpath()
ctx.setFillColor(CGColor(red: 0.17, green: 0.63, blue: 0.72, alpha: 0.23))
ctx.setStrokeColor(CGColor(red: 0.46, green: 0.90, blue: 0.88, alpha: 1))
ctx.setLineWidth(31)
ctx.setLineJoin(.round)
ctx.addPath(shield)
ctx.drawPath(using: .fillStroke)
ctx.move(to: CGPoint(x: 402, y: 512))
ctx.addLine(to: CGPoint(x: 480, y: 430))
ctx.addLine(to: CGPoint(x: 627, y: 584))
ctx.setStrokeColor(CGColor(red: 0.88, green: 1, blue: 0.98, alpha: 1))
ctx.setLineWidth(40)
ctx.setLineCap(.round)
ctx.strokePath()
let bitmap = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
