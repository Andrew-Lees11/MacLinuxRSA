import OpenSSL
import Foundation

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
        print("data.count: \(data.count)")
        var evp_key = EVP_PKEY_new()
        var status = EVP_PKEY_set1_RSA(evp_key, nativeKey)
        guard status == 1 else {
            return nil
        }
        
        // Size of symmetric encryption
        let encKeyLength = Int(EVP_PKEY_size(evp_key))
        let encIVLength = 16
        // Size of encryptedKey
        let encryptedDataLength = Int(data.count) - encKeyLength - 16
        
        // Extract encryptedKey, encryptedData, encryptedIV from data
        let encryptedKey = data.subdata(in: 0..<encKeyLength)
        // 16-byte Zero IV to match Apple platform
        let encryptedIV = Data(repeating: 0, count: encIVLength)
        let encryptedData = data.subdata(in: encKeyLength..<encKeyLength+encryptedDataLength)
        var tagData = data.subdata(in: encKeyLength+encryptedDataLength..<data.count)
        
        let rsaDecryptCtx = EVP_CIPHER_CTX_new_wrapper()
        defer {
            EVP_CIPHER_CTX_reset_wrapper(rsaDecryptCtx)
            EVP_CIPHER_CTX_free_wrapper(rsaDecryptCtx)
            EVP_PKEY_free(evp_key)
        }
        
        EVP_CIPHER_CTX_set_padding(rsaDecryptCtx, RSA_PKCS1_OAEP_PADDING)
        EVP_CIPHER_CTX_ctrl(rsaDecryptCtx, EVP_CTRL_GCM_SET_IVLEN, 16, nil)

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
            print("status: \(status)")
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
    
    func decryptParts(_ data: Data) -> Data? {
        print("data.count: \(data.count)")
        var evp_key = EVP_PKEY_new()
        var status = EVP_PKEY_set1_RSA(evp_key, nativeKey)
        guard status == 1 else {
            return nil
        }
        
        // Size of symmetric encryption
        let encKeyLength = Int(EVP_PKEY_size(evp_key))
        print("encKeyLength: \(encKeyLength)")
        let encIVLength = 16
        // Size of encryptedKey
        let encryptedDataLength = Int(data.count) - encKeyLength - 16
        
        // Extract encryptedKey, encryptedData, encryptedIV from data
        let encryptedKey = data.subdata(in: 0..<encKeyLength)
        // 16-byte Zero IV to match Apple platform
        let encryptedIV = [UInt8](repeating: 0, count: 16)
        let encryptedData = data.subdata(in: encKeyLength..<encKeyLength+encryptedDataLength)
        var tagData = data.subdata(in: encKeyLength+encryptedDataLength..<data.count)
        
        let key = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        print(RSA_private_decrypt(Int32(encryptedKey.count), [UInt8](encryptedKey), key, nativeKey, RSA_PKCS1_OAEP_PADDING))
        let rsaDecryptCtx = EVP_CIPHER_CTX_new_wrapper()
        defer {
            EVP_CIPHER_CTX_reset_wrapper(rsaDecryptCtx)
            EVP_CIPHER_CTX_free_wrapper(rsaDecryptCtx)
            EVP_PKEY_free(evp_key)
            key.deallocate()
        }
        print(EVP_DecryptInit_ex(rsaDecryptCtx, EVP_aes_128_gcm(), nil, nil, nil))
        print(EVP_CIPHER_CTX_ctrl(rsaDecryptCtx, EVP_CTRL_GCM_SET_IVLEN, 16, nil))
        print(EVP_CIPHER_CTX_set_padding(rsaDecryptCtx, RSA_PKCS1_OAEP_PADDING))
        print(EVP_CIPHER_CTX_set_key_length(rsaDecryptCtx, 16))
        print(EVP_DecryptInit_ex(rsaDecryptCtx, nil, nil, key, encryptedIV))
        var processedLen: Int32 = 0
        var decMsgLen: Int32 = 0
        let aad = [UInt8](Data(base64Encoded: "MIGJAoGBAKoYq6Q7UN7vOFmPr4fSq2NORXHBMKm8p7h4JnQU+quLRxvYll9cn8OBhIXq9SnCYkbzBVBkqN4ZyMM4vlSWy66wWdwLNYFDtEo1RJ6yZBExIaRVvX/eP6yRnpS1b7m7T2Uc2yPq1DnWzVI+sIGR51s1/ROnQZswkPJHh71PThlnAgMBAAE=")!)
        print(EVP_DecryptUpdate(rsaDecryptCtx, nil, &processedLen, aad, Int32(aad.count)))

        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptedData.count + encryptedIV.count))
        print(encryptedData.withUnsafeBytes({ (enc: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DecryptUpdate(rsaDecryptCtx, decrypted, &processedLen, enc, Int32(encryptedData.count))
        }))
        decMsgLen += processedLen
        print(tagData.withUnsafeMutableBytes({ (tag: UnsafeMutablePointer<UInt8>) -> Int32 in
            return EVP_CIPHER_CTX_ctrl(rsaDecryptCtx, EVP_CTRL_GCM_SET_TAG, 16, tag)
        }))
        print("decMsgLen: \(decMsgLen)")
        print(EVP_DecryptFinal_ex(rsaDecryptCtx, decrypted.advanced(by: Int(decMsgLen)), &processedLen))
        decMsgLen += processedLen
        decrypted.deallocate()
        return Data(bytes: decrypted, count: Int(decMsgLen))
    }
}
