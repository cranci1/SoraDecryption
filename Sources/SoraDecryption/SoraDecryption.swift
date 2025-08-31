// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import CommonCrypto

// MARK: - SoraDecryption
public struct SoraDecryption {
    private static let key1 = "deadbeef12345678"
    private static let key2 = "cafebabe87654321"
    private static let key3 = "feedface13579bdf"
    private static let key4 = "baddcafe97531468"
    
    private static let p1 = "afd68119"
    private static let p2 = "f7afc868"
    private static let p3 = "797124fd"
    private static let p4 = "1941f6e0"
    private static let p5 = "d04e6dce"
    private static let p6 = "f9e9fc41"
    private static let p7 = "f858e2a0"
    private static let p8 = "ba33d4fb"
    
    private static var vectorData: Data {
        var iv = Data()
        for _ in 0..<16 { iv.append(0) }
        return iv
    }
    
    private static func parseHexSequence(_ sequence: String) -> Data {
        var result = Data()
        var hexStr = sequence
        
        while hexStr.count >= 2 {
            let startIdx = hexStr.startIndex
            let endIdx = hexStr.index(startIdx, offsetBy: 2)
            let hexPair = String(hexStr[startIdx..<endIdx])
            
            if let byteVal = UInt8(hexPair, radix: 16) {
                result.append(byteVal)
            }
            
            hexStr = String(hexStr[endIdx...])
        }
        
        return result
    }
    
    private static var secretData: Data {
        let keyComponents = [p1, p2, p3, p4, p5, p6, p7, p8]
        let reconstructedKey = keyComponents.joined()
        return parseHexSequence(reconstructedKey)
    }
    
    /**
     * Encrypt data using AES-256-CBC with dynamic key and IV construction
     */
    public static func processEncryption(inputData: Data) -> Data? {
        let cryptoKey = secretData
        let initVector = vectorData
        
        let paddedInput = applyBlockPadding(to: inputData, size: 16)
        
        let bufferCapacity = paddedInput.count + kCCBlockSizeAES128
        var outputBuffer = Data(count: bufferCapacity)
        var bytesProcessed: size_t = 0
        
        let operationResult = outputBuffer.withUnsafeMutableBytes { outputPtr in
            paddedInput.withUnsafeBytes { inputPtr in
                cryptoKey.withUnsafeBytes { keyPtr in
                    initVector.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyPtr.bindMemory(to: UInt8.self).baseAddress,
                            cryptoKey.count,
                            ivPtr.bindMemory(to: UInt8.self).baseAddress,
                            inputPtr.bindMemory(to: UInt8.self).baseAddress,
                            paddedInput.count,
                            outputPtr.bindMemory(to: UInt8.self).baseAddress,
                            bufferCapacity,
                            &bytesProcessed
                        )
                    }
                }
            }
        }
        
        guard operationResult == kCCSuccess else {
            print("Encryption operation failed with code: \(operationResult)")
            return nil
        }
        
        return Data(outputBuffer.prefix(bytesProcessed))
    }
    
    /**
     * Decrypt data using AES-256-CBC with dynamic key and IV construction
     */
    public static func processDecryption(encryptedData: Data) -> Data? {
        let cryptoKey = secretData
        let initVector = vectorData
        
        let bufferCapacity = encryptedData.count + kCCBlockSizeAES128
        var outputBuffer = Data(count: bufferCapacity)
        var bytesProcessed: size_t = 0
        
        let operationResult = outputBuffer.withUnsafeMutableBytes { outputPtr in
            encryptedData.withUnsafeBytes { inputPtr in
                cryptoKey.withUnsafeBytes { keyPtr in
                    initVector.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyPtr.bindMemory(to: UInt8.self).baseAddress,
                            cryptoKey.count,
                            ivPtr.bindMemory(to: UInt8.self).baseAddress,
                            inputPtr.bindMemory(to: UInt8.self).baseAddress,
                            encryptedData.count,
                            outputPtr.bindMemory(to: UInt8.self).baseAddress,
                            bufferCapacity,
                            &bytesProcessed
                        )
                    }
                }
            }
        }
        
        guard operationResult == kCCSuccess else {
            print("Decryption operation failed with code: \(operationResult)")
            return nil
        }
        
        let decryptedOutput = Data(outputBuffer.prefix(bytesProcessed))
        return stripBlockPadding(from: decryptedOutput)
    }
    
    /**
     * Apply block cipher padding to input data
     */
    private static func applyBlockPadding(to inputData: Data, size blockSize: Int) -> Data {
        let paddingRequired = blockSize - (inputData.count % blockSize)
        let paddingValue = UInt8(paddingRequired)
        var result = inputData
        
        for _ in 0..<paddingRequired {
            result.append(paddingValue)
        }
        
        return result
    }
    
    /**
     * Remove block cipher padding from output data
     */
    private static func stripBlockPadding(from outputData: Data) -> Data? {
        guard !outputData.isEmpty else { return nil }
        
        let paddingValue = Int(outputData.last!)
        guard paddingValue > 0 && paddingValue <= 16 else { return nil }
        guard outputData.count >= paddingValue else { return nil }
        
        let paddingStartIndex = outputData.count - paddingValue
        for idx in paddingStartIndex..<outputData.count {
            if outputData[idx] != UInt8(paddingValue) {
                return nil
            }
        }
        
        return outputData.prefix(paddingStartIndex)
    }
    
    /**
     * Process file encryption from filesystem path
     */
    public static func processFileEncryption(fromPath filePath: String) -> Data? {
        guard let fileContents = FileManager.default.contents(atPath: filePath) else {
            print("Unable to access file at location: \(filePath)")
            return nil
        }
        
        return processEncryption(inputData: fileContents)
    }
    
    /**
     * Process decryption and convert output to UTF-8 string
     */
    public static func processDecryptionToText(from encryptedData: Data) -> String? {
        guard let decryptedOutput = processDecryption(encryptedData: encryptedData) else {
            return nil
        }
        
        return String(data: decryptedOutput, encoding: .utf8)
    }
    
    public static func encrypt(data: Data) -> Data? {
        return processEncryption(inputData: data)
    }
    
    public static func decrypt(data: Data) -> Data? {
        return processDecryption(encryptedData: data)
    }
    
    public static func encryptFile(at path: String) -> Data? {
        return processFileEncryption(fromPath: path)
    }
    
    public static func decryptToString(data: Data) -> String? {
        return processDecryptionToText(from: data)
    }
}
