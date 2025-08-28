import XCTest
@testable import SoraDecryption
import CommonCrypto

final class SoraDecryptTests: XCTestCase {
    func testDecrypt() throws {
        let sut = SoraDecryption()
        let key = "afd68119f7afc868797124fd1941f6e0d04e6dcef9e9fc41f858e2a0ba33d4fb"
        let keyData = key.sha256()
        
        let iv = Data((0..<16).map { UInt8($0) })
        
        let plaintext = "Paul Freaky, and craci even more"
        let plainData = plaintext.data(using: .utf8)!
        var outData = Data(count: plainData.count + kCCBlockSizeAES128)
        var outLen: size_t = 0
        
        var status: Int32 = -1
        var cipher = outData
        let cipherCount = cipher.count
        status = cipher.withUnsafeMutableBytes { outPtr in
            plainData.withUnsafeBytes { inPtr in
                keyData.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress,
                            keyData.count,
                            ivPtr.baseAddress,
                            inPtr.baseAddress,
                            plainData.count,
                            outPtr.baseAddress,
                            cipherCount,
                            &outLen
                        )
                    }
                }
            }
        }
        
        XCTAssertEqual(status, Int32(kCCSuccess))
        cipher.removeLast(cipher.count - outLen)
        outData = cipher
        
        func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        let ivHex = hex(iv)
        let cipherHex = hex(outData)
        let combined = ivHex + ":" + cipherHex
        
        let decrypted = sut.decrypt(combined)
        XCTAssertEqual(decrypted, plaintext)
    }
}
