//
//  utils.swift
//  OpenSSLSeckey
//
//  Created by Andrew Lees on 08/02/2019.
//

import Foundation

struct Utils {
    static func stripX509CertificateHeader(for keyData: Data) -> Data? {
        
        let count = keyData.count / MemoryLayout<CUnsignedChar>.size
        
        guard count > 0 else {
            
            return nil
        }
        
        var byteArray = [UInt8](keyData)
        
        var index = 0
        guard byteArray[index] == 0x30 else {
            
            return nil
        }
        
        index += 1
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        } else {
            index += 1
        }
        
        // If current byte marks an integer (0x02), it means the key doesn't have a X509 header and just
        // contains its modulo & public exponent. In this case, we can just return the provided DER data as is.
        if Int(byteArray[index]) == 0x02 {
            return keyData
        }
        
        // Now that we've excluded the possibility of headerless key, we're looking for a valid X509 header sequence.
        // It should look like this:
        // 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        guard Int(byteArray[index]) == 0x30 else {
            
            return nil
        }
        
        index += 15
        if byteArray[index] != 0x03 {
            
            return nil
        }
        
        index += 1
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        } else {
            index += 1
        }
        
        guard byteArray[index] == 0 else {
            
            return nil
        }
        
        index += 1
        
        let strippedKeyBytes = [UInt8](byteArray[index...keyData.count - 1])
        let data = Data(bytes: UnsafePointer<UInt8>(strippedKeyBytes), count: keyData.count - index)
        
        return data
    }
    
    static func base64String(for pemString: String) -> String? {
        
        // Filter looking for new lines...
        var lines = pemString.components(separatedBy: "\n").filter { line in
            return !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
        }
        
        // No lines, no data...
        guard lines.count != 0 else {
            return nil
        }
        
        // Strip off any carriage returns...
        lines = lines.map { $0.replacingOccurrences(of: "\r", with: "") }
        
        return lines.joined(separator: "")
    }
}
