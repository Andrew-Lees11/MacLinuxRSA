import OpenSSL
import Foundation

struct OpenSSLPubKey {
    let nativeKey: UnsafeMutablePointer<RSA>?
    init?(pem: String) {
        guard let key = pem.data(using: .utf8) else {
            return nil
        }
        let bio = BIO_new(BIO_s_mem())
        key.withUnsafeBytes { (bytes: UnsafePointer<Int8>) -> Void in
            BIO_puts(bio, bytes)
        }
        let evpKey = PEM_read_bio_PUBKEY(bio, nil, nil, nil)
        let nativekey = EVP_PKEY_get1_RSA(evpKey)
        BIO_free(bio)
        self.nativeKey = nativekey
    }
    
    func encrypt(_ data: Data) -> Data? {
        var evp_key = EVP_PKEY_new()
        var rc = EVP_PKEY_set1_RSA(evp_key, nativeKey)
        guard rc == 1 else {
            return nil
        }
        
        let rsaEncryptCtx = EVP_CIPHER_CTX_new_wrapper()
        
        defer {
            EVP_CIPHER_CTX_reset_wrapper(rsaEncryptCtx)
            EVP_CIPHER_CTX_free_wrapper(rsaEncryptCtx)
            EVP_PKEY_free(evp_key)
        }
        
        EVP_CIPHER_CTX_set_padding(rsaEncryptCtx, RSA_PKCS1_OAEP_PADDING)
        
        // Initialize the AES encryption key array (of size 1)
        var ek: UnsafeMutablePointer<UInt8>?
        ek = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(EVP_PKEY_size(evp_key)))
        let ekPtr = UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>.allocate(capacity: MemoryLayout<UnsafeMutablePointer<UInt8>?>.size)
        ekPtr.pointee = ek
        
        // Assign size of the corresponding cipher's IV
        let IVLength = EVP_CIPHER_iv_length(EVP_aes_128_gcm())
        let iv = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(IVLength))
        let encrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count + Int(IVLength))
        var encKeyLength: Int32 = 0
        var processedLength: Int32 = 0
        var encLength: Int32 = 0
        
        // Initializes a cipher context ctx for encryption with cipher type using a random secret key and IV.
        // The secret key is encrypted using the public key (evp_key can be an array of public keys)
        // Here we are using just 1 public key
        var status = EVP_SealInit(rsaEncryptCtx, EVP_aes_128_gcm(), ekPtr, &encKeyLength, iv, &evp_key, 1)
        
        // SealInit should return the number of public keys that were input, here it is only 1
        guard status == 1 else {
            return nil
        }
        
        // EVP_SealUpdate is a complex macros and therefore the compiler doesnt
        // convert it directly to swift. From /usr/local/opt/openssl/include/openssl/evp.h:
        _ = data.withUnsafeBytes({ (plaintext: UnsafePointer<UInt8>) -> Int32 in
            return EVP_EncryptUpdate(rsaEncryptCtx, encrypted, &processedLength, plaintext, Int32(data.count))
        })
        encLength = processedLength
        
        status = EVP_SealFinal(rsaEncryptCtx, encrypted.advanced(by: Int(encLength)), &processedLength)
        guard status == 1 else {
            return nil
        }
        encLength += processedLength
        
        let tag = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        status = EVP_CIPHER_CTX_ctrl(rsaEncryptCtx, EVP_CTRL_GCM_GET_TAG, 16, tag)
        guard status == 1 else {
            return nil
        }
        let tagFinal = Data(bytes: tag, count: 16)
        let cipher = Data(bytes: encrypted, count: Int(encLength))
        let ekFinal = Data(bytes: ek!, count: Int(encKeyLength))
        let ivFinal = Data(bytes: iv, count: Int(IVLength))
        
        print("ekFinal: \(ekFinal.count), cipher: \(cipher.count), tagFinal: \(tagFinal.count)")
        return ekFinal + ivFinal + cipher + tagFinal
    }
}

struct OpenSSLPrivKey {
    let nativeKey: UnsafeMutablePointer<RSA>?
    init?(pem: String) {
        guard let key = pem.data(using: .utf8) else {
            return nil
        }
        let bio = BIO_new(BIO_s_mem())
        key.withUnsafeBytes { (bytes: UnsafePointer<Int8>) -> Void in
            BIO_puts(bio, bytes)
        }
        let evpKey = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
        let nativekey = EVP_PKEY_get1_RSA(evpKey)
        BIO_free(bio)
        self.nativeKey = nativekey
    }
    
    func decrypt(_ data: Data) -> Data? {
        var evp_key = EVP_PKEY_new()
        var status = EVP_PKEY_set1_RSA(evp_key, nativeKey)
        guard status == 1 else {
            return nil
        }
        
        // Size of symmetric encryption
        let encKeyLength = Int(EVP_PKEY_size(evp_key))
        // Size of the corresponding cipher's IV
        let encIVLength = Int(EVP_CIPHER_iv_length(EVP_aes_128_gcm()))
        // Size of encryptedKey
        let encryptedDataLength = Int(data.count) - encKeyLength - encIVLength - 16
        
        // Extract encryptedKey, encryptedData, encryptedIV from data
        let encryptedKey = data.subdata(in: 0..<encKeyLength)
        let encryptedIV = data.subdata(in: encKeyLength..<encKeyLength+encIVLength)
        guard encKeyLength+encIVLength < encKeyLength+encIVLength+encryptedDataLength else {
            return nil
        }
        let encryptedData = data.subdata(in: encKeyLength+encIVLength..<encKeyLength+encIVLength+encryptedDataLength)
        var tagData = data.subdata(in: encKeyLength+encIVLength+encryptedDataLength..<data.count)
        
        let rsaDecryptCtx = EVP_CIPHER_CTX_new_wrapper()
        
        defer {
            EVP_CIPHER_CTX_reset_wrapper(rsaDecryptCtx)
            EVP_CIPHER_CTX_free_wrapper(rsaDecryptCtx)
            EVP_PKEY_free(evp_key)
        }
        
        EVP_CIPHER_CTX_set_padding(rsaDecryptCtx, RSA_PKCS1_OAEP_PADDING)
        
        // processedLen is the number of bytes that each EVP_DecryptUpdate/EVP_DecryptFinal decrypts.
        // The sum of processedLen is the total size of the decrypted message (decMsgLen)
        var processedLen: Int32 = 0
        var decMsgLen: Int32 = 0
        
        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptedData.count + encryptedIV.count))
        
        // EVP_OpenInit returns 0 on error or the recovered secret key size if successful
        status = encryptedKey.withUnsafeBytes({ (ek: UnsafePointer<UInt8>) -> Int32 in
            return encryptedIV.withUnsafeBytes({ (iv: UnsafePointer<UInt8>) -> Int32 in
                return EVP_OpenInit(rsaDecryptCtx, EVP_aes_128_gcm(), ek, Int32(encryptedKey.count), iv, evp_key)
            })
        })
        guard status != 0 else {
            return nil
        }
        
        // EVP_OpenUpdate is a complex macros and therefore the compiler doesnt
        // convert it directly to Swift. From /usr/local/opt/openssl/include/openssl/evp.h:
        _ = encryptedData.withUnsafeBytes({ (enc: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DecryptUpdate(rsaDecryptCtx, decrypted, &processedLen, enc, Int32(encryptedData.count))
        })
        decMsgLen = processedLen
        status = tagData.withUnsafeMutableBytes({ (tag: UnsafeMutablePointer<UInt8>) -> Int32 in
            return EVP_CIPHER_CTX_ctrl(rsaDecryptCtx, EVP_CTRL_GCM_SET_TAG, 16, tag)
        })
        guard status == 1 else {
            return nil
        }
        status = EVP_OpenFinal(rsaDecryptCtx, decrypted.advanced(by: Int(decMsgLen)), &processedLen)
        guard status != 0 else {
            return nil
        }
        decMsgLen += processedLen
        
        return Data(bytes: decrypted, count: Int(decMsgLen))
    }
    
    func decryptNoIV(_ data: Data) -> Data? {
        var evp_key = EVP_PKEY_new()
        var status = EVP_PKEY_set1_RSA(evp_key, nativeKey)
        guard status == 1 else {
            return nil
        }
        
        // Size of symmetric encryption
        let encKeyLength = Int(EVP_PKEY_size(evp_key))
        // Size of encryptedKey
        let encryptedDataLength = Int(data.count) - encKeyLength - 16
        
        // Extract encryptedKey, encryptedData, encryptedIV from data
        let encryptedKey = data.subdata(in: 0..<encKeyLength)
        let encryptedIV = Data(repeating: 0, count: 12)
        guard encKeyLength < encKeyLength+encryptedDataLength else {
            return nil
        }
        let encryptedData = data.subdata(in: encKeyLength..<encKeyLength+encryptedDataLength)
        var tagData = data.subdata(in: encKeyLength+encryptedDataLength..<data.count)
        
        let rsaDecryptCtx = EVP_CIPHER_CTX_new_wrapper()
        
        defer {
            EVP_CIPHER_CTX_reset_wrapper(rsaDecryptCtx)
            EVP_CIPHER_CTX_free_wrapper(rsaDecryptCtx)
            EVP_PKEY_free(evp_key)
        }
        
        EVP_CIPHER_CTX_set_padding(rsaDecryptCtx, RSA_PKCS1_OAEP_PADDING)
        
        // processedLen is the number of bytes that each EVP_DecryptUpdate/EVP_DecryptFinal decrypts.
        // The sum of processedLen is the total size of the decrypted message (decMsgLen)
        var processedLen: Int32 = 0
        var decMsgLen: Int32 = 0
        
        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptedData.count + encryptedIV.count))
        
        // EVP_OpenInit returns 0 on error or the recovered secret key size if successful
        status = encryptedKey.withUnsafeBytes({ (ek: UnsafePointer<UInt8>) -> Int32 in
            return encryptedIV.withUnsafeBytes({ (iv: UnsafePointer<UInt8>) -> Int32 in
                return EVP_OpenInit(rsaDecryptCtx, EVP_aes_128_gcm(), ek, Int32(encryptedKey.count), iv, evp_key)
            })
        })
        guard status != 0 else {
            return nil
        }
        
        // EVP_OpenUpdate is a complex macros and therefore the compiler doesnt
        // convert it directly to Swift. From /usr/local/opt/openssl/include/openssl/evp.h:
        _ = encryptedData.withUnsafeBytes({ (enc: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DecryptUpdate(rsaDecryptCtx, decrypted, &processedLen, enc, Int32(encryptedData.count))
        })
        decMsgLen = processedLen
        status = tagData.withUnsafeMutableBytes({ (tag: UnsafeMutablePointer<UInt8>) -> Int32 in
            return EVP_CIPHER_CTX_ctrl(rsaDecryptCtx, EVP_CTRL_GCM_SET_TAG, 16, tag)
        })
        guard status == 1 else {
            return nil
        }
        status = EVP_OpenFinal(rsaDecryptCtx, decrypted.advanced(by: Int(decMsgLen)), &processedLen)
        guard status != 0 else {
            return nil
        }
        decMsgLen += processedLen
        
        return Data(bytes: decrypted, count: Int(decMsgLen))
    }
}

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
                                                    SecKeyAlgorithm.rsaEncryptionOAEPSHA256AESGCM,
                                                    data as CFData,
                                                    &response) else {
            return nil
        }
        if response != nil {
            
            guard let error = response?.takeRetainedValue() else {
                return nil
            }
            print(error)
            return nil
        }
        
        return (pData as Data)
    }
}

