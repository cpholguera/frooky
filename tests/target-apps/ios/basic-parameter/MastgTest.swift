import SwiftUI
import Foundation

struct MastgTest {

    enum Direction: String {
        case north = "NORTH"
        case south = "SOUTH"
        case east  = "EAST"
        case west  = "WEST"
    }

    // Single types
    static func passString(_ arg: String) -> String { arg }
    static func passBool(_ arg: Bool) -> Bool { arg }
    static func passInt8(_ arg: Int8) -> Int8 { arg }
    static func passInt16(_ arg: Int16) -> Int16 { arg }
    static func passInt32(_ arg: Int32) -> Int32 { arg }
    static func passInt64(_ arg: Int64) -> Int64 { arg }
    static func passFloat(_ arg: Float) -> Float { arg }
    static func passDouble(_ arg: Double) -> Double { arg }
    static func passChar(_ arg: Character) -> Character { arg }

    // Big number types
    static func passDecimalNumber(_ arg: NSDecimalNumber) -> NSDecimalNumber { arg }

    // Collections
    static func passList(_ arg: [String]) -> [String] { arg }
    static func passMap(_ arg: [String: String]) -> [String: String] { arg }
    static func passSet(_ arg: Set<String>) -> Set<String> { arg }
    static func passEnum(_ arg: Direction) -> Direction { arg }

    // Arrays
    static func passStringArray(_ arg: [String]) -> [String] { arg }
    static func passBoolArray(_ arg: [Bool]) -> [Bool] { arg }
    static func passInt8Array(_ arg: [Int8]) -> [Int8] { arg }
    static func passInt16Array(_ arg: [Int16]) -> [Int16] { arg }
    static func passInt32Array(_ arg: [Int32]) -> [Int32] { arg }
    static func passInt64Array(_ arg: [Int64]) -> [Int64] { arg }
    static func passFloatArray(_ arg: [Float]) -> [Float] { arg }
    static func passDoubleArray(_ arg: [Double]) -> [Double] { arg }
    static func passCharArray(_ arg: [Character]) -> [Character] { arg }

    static func mastgTest(completion: @escaping (String) -> Void) {
        let r = DemoResults(demoId: "basic-parameter")

        r.add(status: .pass, message: passString("Test String"))
        r.add(status: .pass, message: String(passBool(true)))
        r.add(status: .pass, message: String(passInt8(127)))
        r.add(status: .pass, message: String(passInt16(32767)))
        r.add(status: .pass, message: String(passInt32(2_147_483_647)))
        r.add(status: .pass, message: String(passInt64(9_223_372_036_854_775_807)))
        r.add(status: .pass, message: String(passFloat(3.14)))
        r.add(status: .pass, message: String(passDouble(3.141592653589793)))
        r.add(status: .pass, message: String(passChar("A")))

        r.add(status: .pass, message: passStringArray(["a", "b", "c"]).joined(separator: ", "))
        r.add(status: .pass, message: passBoolArray([true, false]).map { String($0) }.joined(separator: ", "))
        r.add(status: .pass, message: passInt8Array([1, 2, 3]).map { String($0) }.joined(separator: ", "))
        r.add(status: .pass, message: passInt16Array([1, 2, 3]).map { String($0) }.joined(separator: ", "))
        r.add(status: .pass, message: passInt32Array([1, 2, 3]).map { String($0) }.joined(separator: ", "))
        r.add(status: .pass, message: passInt64Array([1, 2, 3]).map { String($0) }.joined(separator: ", "))
        r.add(status: .pass, message: passFloatArray([1.1, 2.2]).map { String($0) }.joined(separator: ", "))
        r.add(status: .pass, message: passDoubleArray([1.1, 2.2]).map { String($0) }.joined(separator: ", "))
        r.add(status: .pass, message: passCharArray(["x", "y", "z"]).map { String($0) }.joined(separator: ", "))

        r.add(status: .pass, message: passDecimalNumber(NSDecimalNumber(string: "3.141592653589793238462643383")).stringValue)
        r.add(status: .pass, message: passList(["a", "b", "c"]).description)
        r.add(status: .pass, message: passMap(["key": "value"]).description)
        r.add(status: .pass, message: passSet(["a", "b", "c"]).sorted().description)
        r.add(status: .pass, message: passEnum(.north).rawValue)

        completion(r.toJson())
    }
}
