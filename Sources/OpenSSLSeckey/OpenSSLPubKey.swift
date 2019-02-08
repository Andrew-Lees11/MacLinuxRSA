import OpenSSL
import Foundation

@available(OSX 10.12, *)
struct OpenSSLPubKey {
    let nativeKey: UnsafeMutablePointer<RSA>?
    init?(pem: String) {
        guard let der = Utils.pemToASN1(key: pem) else {
            return nil
        }
        print("pubkey der: \(der.base64EncodedString())")
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
    
    func encryptNoIV(_ data: Data) -> Data? {
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
        EVP_CIPHER_CTX_ctrl(rsaEncryptCtx, EVP_CTRL_GCM_SET_IVLEN, 16, nil)

        // Initialize the AES encryption key array (of size 1)
        var ek: UnsafeMutablePointer<UInt8>?
        ek = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(EVP_PKEY_size(evp_key)))
        let ekPtr = UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>.allocate(capacity: MemoryLayout<UnsafeMutablePointer<UInt8>?>.size)
        ekPtr.pointee = ek
        
        // Assign size of the corresponding cipher's IV
        let IVLength = 16
        let tagLength = 16
        let iv = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(IVLength))
        print("encrypt: IV length = \(IVLength)")
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
        var bytes: [UInt8] = [UInt8](repeating: 0x0, count: IVLength)
        iv.initialize(from: &bytes, count: IVLength)
        status = EVP_EncryptInit_ex(rsaEncryptCtx, nil, nil, nil, iv)
        guard status == 1 else {
            return nil
        }
//        let keyData = Data(base64Encoded: "MIGJAoGBAKoYq6Q7UN7vOFmPr4fSq2NORXHBMKm8p7h4JnQU+quLRxvYll9cn8OBhIXq9SnCYkbzBVBkqN4ZyMM4vlSWy66wWdwLNYFDtEo1RJ6yZBExIaRVvX/eP6yRnpS1b7m7T2Uc2yPq1DnWzVI+sIGR51s1/ROnQZswkPJHh71PThlnAgMBAAE=")!
//        let derBytes = [UInt8](keyData)
//        let aardResult = EVP_EncryptUpdate(rsaEncryptCtx, nil, &processedLength, derBytes, Int32(derBytes.count))
//        guard aardResult == 1 else {
//            return nil
//        }
//        encLength = processedLength
        
        // EVP_SealUpdate is a complex macros and therefore the compiler doesnt
        // convert it directly to swift. From /usr/local/opt/openssl/include/openssl/evp.h:
        _ = data.withUnsafeBytes({ (plaintext: UnsafePointer<UInt8>) -> Int32 in
            return EVP_EncryptUpdate(rsaEncryptCtx, encrypted, &processedLength, plaintext, Int32(data.count))
        })
        encLength += processedLength
        
        status = EVP_SealFinal(rsaEncryptCtx, encrypted.advanced(by: Int(encLength)), &processedLength)
        guard status == 1 else {
            return nil
        }
        encLength += processedLength
        let tag = UnsafeMutablePointer<UInt8>.allocate(capacity: tagLength)
        status = EVP_CIPHER_CTX_ctrl(rsaEncryptCtx, EVP_CTRL_GCM_GET_TAG, Int32(tagLength), tag)
        guard status == 1 else {
            return nil
        }
        let tagFinal = Data(bytes: tag, count: 16)
        let cipher = Data(bytes: encrypted, count: Int(encLength))
        let ekFinal = Data(bytes: ek!, count: Int(encKeyLength))
        
        print("ekFinal: \(ekFinal.count), cipher: \(cipher.count), tagFinal: \(tagFinal.count)")
        return ekFinal + cipher + tagFinal
    }
}
