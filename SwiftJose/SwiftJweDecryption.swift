//
//  SwiftJweDecryption.swift
//  SwiftJose
//
//  Created by rmtmckenzie on 17/11/2016.
//  Copyright © 2016 rmtmckenzie. All rights reserved.
//

import Foundation
import SwCrypt

protocol ContentDecryptionAlgorithm {
    func decrypt(encryptedKey: Data, iv: Data, cipherText : Data, tag: Data, aad: Data) throws -> String
}

protocol ContentDecryptionKey {
    func getDecryptor(_ enc: String) throws -> ContentDecryptionAlgorithm
}

class AesContentDecryptionKey : ContentDecryptionKey {
    var key: Data
    
    init(_ keyData : Data) {
        key = keyData
    }
    
    public func getDecryptor(_ enc : String) throws -> ContentDecryptionAlgorithm{
        switch enc {
        case "A256GCM":
            return ContentDecryptionAes256Gcm(key)
        default:
            throw JwError.unsupportedDecryptionEncryptionMethod(enc: enc)
        }
    }
}

class ContentDecryptionAes256Gcm : ContentDecryptionAlgorithm {
    public var keyData: Data
    
    init (_ keyData: Data) {
        self.keyData = keyData
    }
    
    public func decrypt(encryptedKey: Data,iv: Data, cipherText : Data, tag: Data, aad: Data) throws -> String {
        let (plaintext, testTag) = try CC.GCM.crypt(.decrypt, algorithm: .aes, data: cipherText, key: keyData, iv: iv, aData: aad, tagLength: JwConstants.tagLength)
        
        guard testTag == tag else {
            throw JwError.tagMismatch(expectedTag: tag, calculatedTag: testTag)
        }
        
        return String(data: plaintext, encoding: String.Encoding.utf8)!
    }
}

class SwiftJweParser : JweDecryptionKeyManagement, JweDirectContentDecryption, JweDecryptionPerformer {
    
    var tokenProvider : TokenProvider
    var decryptionKey : ContentDecryptionKey?
    var encryptionAlgorithm : String?
    
    init(_ jwParser: TokenProvider) {
        tokenProvider = jwParser
    }
    
    public func direct() -> JweDirectContentDecryption {
        encryptionAlgorithm = "dir"
        return self
    }
    
    public func aes256(_ key: Data) -> JweDecryptionPerformer {
        decryptionKey = AesContentDecryptionKey(key)
        return self
    }
    
    public func perform() throws -> String {
        let decryptionKey = self.decryptionKey!
        let encryptionAlgorithm = self.encryptionAlgorithm!
        
        let token : String = tokenProvider.token
        
        
        let tokenArr = token.components(separatedBy: ".")
        
        guard tokenArr.count == 5 else {
            throw JwError.invalidSectionCount(expectedCount: 5, actualCount: tokenArr.count)
        }
        
        let header = tokenArr[0]
        let encryptedKey = tokenArr[1]
        let initVector = tokenArr[2]
        let cipherText = tokenArr[3]
        let authTag = tokenArr[4]
        
        //TODO: can we use ascii instead of utf8?
        let headerAsData = base64urldecode(header)!
        let headerAsAscii = header.data(using: .ascii)!
        let encryptedKeyData = base64urldecode(encryptedKey)!
        let initVectorAsData = base64urldecode(initVector)!
        let cipherTextAsData = base64urldecode(cipherText)!
        let authTagAsData = base64urldecode(authTag)!
        
        let headerJsonResult = try JSONSerialization.jsonObject(with: headerAsData, options: .mutableContainers)
        
        guard let jsonResult = headerJsonResult as? [String: Any] else {
            throw JwError.jsonDecodeProblem()
        }
        
        let alg = jsonResult["alg"] as! String
        
        guard alg == encryptionAlgorithm else {
            throw JwError.unsupportedDecryptionAlgorithm(alg: alg)
        }
        
        let enc = jsonResult["enc"] as! String
        
        let decryptor = try decryptionKey.getDecryptor(enc)
        
        let plainText = try decryptor.decrypt(encryptedKey: encryptedKeyData, iv: initVectorAsData, cipherText: cipherTextAsData, tag: authTagAsData, aad: headerAsAscii)
        
        return plainText
    }

}
