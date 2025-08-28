// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import CommonCrypto

// MARK: - SoraDecryption
public struct SoraDecryption {
    private let key = "afd68119f7afc868797124fd1941f6e0d04e6dcef9e9fc41f858e2a0ba33d4fb"
    private let keyData: Data
    
    init() {
        keyData = key.sha256()
    }
    
    func decrypt(_ encryptedData: String) -> String? {
        guard let colonIndex = encryptedData.firstIndex(of: ":") else { return nil }
        
        let ivHexSub = encryptedData[..<colonIndex]
        let encryptedHexSub = encryptedData[encryptedData.index(after: colonIndex)...]
        
        guard ivHexSub.count % 2 == 0, encryptedHexSub.count % 2 == 0 else { return nil }
        guard let ivData = Data(hex: String(ivHexSub)), let encryptedBytes = Data(hex: String(encryptedHexSub)) else { return nil }
        
        var decryptedBuffer = Data(count: encryptedBytes.count + kCCBlockSizeAES128)
        var numBytesDecrypted: size_t = 0
        
        let bufferSize = decryptedBuffer.count
        
        let status = decryptedBuffer.withUnsafeMutableBytes { decryptedBytesPtr in
            encryptedBytes.withUnsafeBytes { encryptedBytesPtr in
                keyData.withUnsafeBytes { keyBytesPtr in
                    ivData.withUnsafeBytes { ivBytesPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytesPtr.baseAddress,
                            keyData.count,
                            ivBytesPtr.baseAddress,
                            encryptedBytesPtr.baseAddress,
                            encryptedBytesPtr.count,
                            decryptedBytesPtr.baseAddress,
                            bufferSize,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }
        
        guard status == kCCSuccess else { return nil }
        
        decryptedBuffer.removeLast(decryptedBuffer.count - numBytesDecrypted)
        
        return String(data: decryptedBuffer, encoding: .utf8)
    }
}

// MARK: - Extensions
extension String {
    func sha256() -> Data {
        let data = self.data(using: .utf8)!
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}

extension Data {
    init?(hex: String) {
        let utf8 = Array(hex.utf8)
        let length = utf8.count
        if length & 1 == 1 { return nil }
        var data = Data(capacity: length / 2)
        
        @inline(__always) func nibble(_ c: UInt8) -> UInt8? {
            if c >= 48 && c <= 57 { return c - 48 }
            if c >= 65 && c <= 70 { return c - 55 }
            if c >= 97 && c <= 102 { return c - 87 }
            return nil
        }
        
        var i = 0
        while i < length {
            guard let hi = nibble(utf8[i]), let lo = nibble(utf8[i + 1]) else { return nil }
            data.append((hi << 4) | lo)
            i += 2
        }
        
        self = data
    }
}
