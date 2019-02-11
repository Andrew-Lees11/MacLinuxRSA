import XCTest
@testable import OpenSSLSeckey

@available(OSX 10.12, *)
final class OpenSSLSeckeyTests: XCTestCase {
    func testExample() {
        let rsaPrivateKey = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----
"""
        let rsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0
FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/
3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----
"""
        guard let secPubKey = SecPubKey(pem: rsaPublicKey),
            let secPrivkey = SecPrivKey(pem: rsaPrivateKey),
            let openSSLPubKey = OpenSSLPubKey(pem: rsaPublicKey),
            let openSSLPrivKey = OpenSSLPrivKey(pem: rsaPrivateKey) else {
                return XCTFail()
        }
        guard let secEncrypted = secPubKey.encrypt("Hello".data(using: .utf8)!) else {
            return XCTFail()
        }
        print(secEncrypted.count)
        guard let openSSLEncrypted = openSSLPubKey.encrypt("Hello".data(using: .utf8)!) else {
            return XCTFail()
        }
        guard let noIVEncrypted = openSSLPubKey.encryptNoIV("Hello".data(using: .utf8)!) else {
            return XCTFail()
        }
        print("noIVEncrypted: \(noIVEncrypted), secEncrypted: \(secEncrypted)")
        print("noIVEncryptedcount: \(noIVEncrypted.count), secEncryptedcount: \(secEncrypted.count)")

//        guard let _ = secPrivkey.decrypt(secEncrypted) else {
//            return XCTFail()
//        }
//        guard let _ = openSSLPrivKey.decrypt(openSSLEncrypted) else {
//            return XCTFail()
//        }
        let openSSLNoIV = openSSLPrivKey.decryptNoIV(noIVEncrypted)
//        let secToOpenSSL = openSSLPrivKey.decrypt(secEncrypted)
//        let openSSLToSec = secPrivkey.decrypt(openSSLEncrypted)
        let noIV = openSSLPrivKey.decryptNoIV(secEncrypted)
        let secNoIV = secPrivkey.decrypt(noIVEncrypted)
        print("openSSLNoIV: \(openSSLNoIV)")
//        print("secToOpenSSL: \(secToOpenSSL)")
//        print("openSSLToSec: \(openSSLToSec)")
        print("noIV: \(noIV)")
        print("secNoIV: \(secNoIV)")
    }
    
    func testParts() {
        let rsaPrivateKey = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----
"""
        let rsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0
FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/
3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----
"""
        guard let secPubKey = SecPubKey(pem: rsaPublicKey),
            let secPrivkey = SecPrivKey(pem: rsaPrivateKey),
            let openSSLPubKey = OpenSSLPubKey(pem: rsaPublicKey),
            let openSSLPrivKey = OpenSSLPrivKey(pem: rsaPrivateKey) else {
                return XCTFail()
        }
        guard let secEncrypted = secPubKey.encrypt("Hello".data(using: .utf8)!) else {
            return XCTFail()
        }
        print(secEncrypted.count)
        guard let openSSLEncrypted = openSSLPubKey.encryptNoIV("Hello".data(using: .utf8)!) else {
            return XCTFail()
        }
        guard let openSSLPartsEncrypted = openSSLPubKey.encryptParts("Hello".data(using: .utf8)!) else {
            return XCTFail()
        }
        print("secToOpenSSL")
        guard let secToOpenSSL = openSSLPrivKey.decryptParts(secEncrypted) else {
            return XCTFail()
        }
        print("secToOpenSSL END")
        print("osslToOssl")
        guard let osslToOssl = openSSLPrivKey.decryptParts(openSSLPartsEncrypted) else {
            return XCTFail()
        }
        print("osslToOssl End")
        print(String(data: osslToOssl, encoding: .utf8) as Any)
        
//        let openSSLToSec = secPrivkey.decrypt(openSSLPartsEncrypted)
//        print("openSSLToSec: \(String(describing: openSSLToSec))")
        
    }
    
    func testOSSLtoSEC() {
        let rsaPrivateKey = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----
"""
        let rsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0
FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/
3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----
"""
        guard let secPrivkey = SecPrivKey(pem: rsaPrivateKey),
            let openSSLPubKey = OpenSSLPubKey(pem: rsaPublicKey) else {
                return XCTFail()
        }
        guard let openSSLPartsEncrypted = openSSLPubKey.encryptParts("Hello".data(using: .utf8)!) else {
            return XCTFail()
        }
        let openSSLToSec = secPrivkey.decrypt(openSSLPartsEncrypted)
        print("openSSLToSec: \(String(describing: openSSLToSec))")
        
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
