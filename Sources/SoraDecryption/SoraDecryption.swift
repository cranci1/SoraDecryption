// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import CommonCrypto

// MARK: - SoraDecryption
public struct SoraDecryption {
    private static let keyHex = "afd68119f7afc868797124fd1941f6e0d04e6dcef9e9fc41f858e2a0ba33d4fb"
    private static let ivData = Data(repeating: 0, count: 16)
    
    private static func hexStringToData(_ hex: String) -> Data {
        var data = Data()
        var hex = hex
        
        while hex.count >= 2 {
            let start = hex.startIndex
            let end = hex.index(start, offsetBy: 2)
            let byteString = String(hex[start..<end])
            
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            }
            
            hex = String(hex[end...])
        }
        
        return data
    }
    
    private static var keyData: Data {
        return hexStringToData(keyHex)
    }
    
    /**
     * Decrypt data using AES-256-CBC with fixed key and IV
     */
    public static func decrypt(data: Data) -> Data? {
        let keyData = self.keyData
        let ivData = self.ivData
        
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var numBytesDecrypted: size_t = 0
        
        let cryptStatus = buffer.withUnsafeMutableBytes { bufferBytes in
            data.withUnsafeBytes { dataBytes in
                keyData.withUnsafeBytes { keyBytes in
                    ivData.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyBytes.bindMemory(to: UInt8.self).baseAddress,
                            keyData.count,
                            ivBytes.bindMemory(to: UInt8.self).baseAddress,
                            dataBytes.bindMemory(to: UInt8.self).baseAddress,
                            data.count,
                            bufferBytes.bindMemory(to: UInt8.self).baseAddress,
                            bufferSize,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else {
            print("Decryption failed with status: \(cryptStatus)")
            return nil
        }
        
        let decryptedData = Data(buffer.prefix(numBytesDecrypted))
        return removePKCS7Padding(from: decryptedData)
    }
    
    /**
     * Remove PKCS7 padding from data
     */
    private static func removePKCS7Padding(from data: Data) -> Data? {
        guard !data.isEmpty else { return nil }
        
        let paddingLength = Int(data.last!)
        guard paddingLength > 0 && paddingLength <= 16 else { return nil }
        guard data.count >= paddingLength else { return nil }
        
        let paddingStart = data.count - paddingLength
        for i in paddingStart..<data.count {
            if data[i] != UInt8(paddingLength) {
                return nil
            }
        }
        
        return data.prefix(paddingStart)
    }
    
    /**
     * Decrypt data and return as string (for JavaScript modules)
     */
    public static func decryptToString(data: Data) -> String? {
        guard let decryptedData = decrypt(data: data) else {
            return nil
        }
        
        return String(data: decryptedData, encoding: .utf8)
    }
}
