import OpenSSL
import Foundation

@available(OSX 10.12, *)
struct SecPubKey {
    let nativeKey: SecKey
    init?(pem: String) {
        guard let base64String = Utils.base64String(for: pem),
            let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]),
            let strippedData = Utils.stripX509CertificateHeader(for: data)
            else {
                return nil
        }
        let keyDict: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: strippedData.count * 8
        ]
        
        guard let key = SecKeyCreateWithData(strippedData as CFData, keyDict as CFDictionary, nil) else {
            return nil
        }
        print("SecKey: \((SecKeyCopyExternalRepresentation(key, nil) as! Data).base64EncodedString())")
        self.nativeKey = key
    }
    func encrypt(_ data: Data) -> Data? {
        var response: Unmanaged<CFError>? = nil
        guard let eData = SecKeyCreateEncryptedData(nativeKey,
                                                    SecKeyAlgorithm.rsaEncryptionOAEPSHA256AESGCM,
                                                    data as CFData,
                                                    &response)
            else {
                return nil
        }
        if response != nil {
            
            guard let error = response?.takeRetainedValue() else {
                return nil
            }
            print(error)
            return nil
        }
        return (eData as Data)
    }
}
