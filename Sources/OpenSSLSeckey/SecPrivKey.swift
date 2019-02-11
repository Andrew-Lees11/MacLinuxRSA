import OpenSSL
import Foundation

@available(OSX 10.12, *)
struct SecPrivKey {
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
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: strippedData.count * 8
        ]
        
        guard let key = SecKeyCreateWithData(strippedData as CFData, keyDict as CFDictionary, nil) else {
            return nil
        }
        
        self.nativeKey = key
    }
    
    func decrypt(_ data: Data) -> Data? {
        var response: Unmanaged<CFError>? = nil
        guard let pData = SecKeyCreateDecryptedData(nativeKey,
                                                    SecKeyAlgorithm.rsaEncryptionOAEPSHA1AESGCM,
                                                    data as CFData,
                                                    &response) else {
            guard let error = response?.takeRetainedValue() else {
                return nil
            }
            print(error)
            return nil
        }        
        return (pData as Data)
    }
}

