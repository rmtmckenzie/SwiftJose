//
//  SwiftJweEncryption.swift
//  SwiftJose
//
//  Created by rmtmckenzie on 17/11/2016.
//  Copyright © 2016 rmtmckenzie. All rights reserved.
//

import Foundation
import SwCrypt

protocol KeyManagementAlgorithm {
    func getEncryptedKey(_ contentKey: Data) -> Data
    var algorithmHeader: String { get }
}

class KeyManagementDirect : KeyManagementAlgorithm {
    public func getEncryptedKey(_ contentKey: Data) -> Data {
        return Data()
    }
    
    public var algorithmHeader = "dir"
}

protocol ContentEncryptionAlgorithm {
    func encrypt(_ text: String, _ aad: Data) throws -> (Data, Data)
    var encryptionMethodHeader: String { get }
    var keyData: Data { get }
    var iv: Data { get }
}

class ContentEncryptionAes256Gcm : ContentEncryptionAlgorithm {
    public var keyData : Data
    public var iv : Data
    
    convenience init(_ keyData: Data) {
        self.init(keyData, CC.generateRandom(16))
    }
    
    init(_ keyData: Data, _ iv: Data) {
        self.keyData = keyData
        self.iv = iv
        //TODO: check iv size
    }
    
    
    public func encrypt(_ text: String, _ aad: Data) throws -> (Data, Data) {
        
        let inputData : Data = text.data(using: String.Encoding.utf8)!
        
        return try CC.GCM.crypt(.encrypt, algorithm: .aes, data: inputData, key: keyData, iv: iv, aData: aad, tagLength: JwConstants.tagLength)
    }
    
    public var encryptionMethodHeader = "A256GCM"
}

class SwiftJweBuilder : JweEncryptionKeyManagement, JweEncryptionContentEncryption, JweEncryptionPerformer {
    var textProvider : PlaintextProvider
    var keyManagementAlgorithm : KeyManagementAlgorithm? = nil
    var contentEncryption : ContentEncryptionAlgorithm? = nil
    
    init(_ textProvider: PlaintextProvider) {
        self.textProvider = textProvider
    }
    
    public func direct() -> JweEncryptionContentEncryption {
        keyManagementAlgorithm = KeyManagementDirect()
        return self
    }
    
    public func aes256gcm(_ key: Data) -> JweEncryptionPerformer {
        contentEncryption = ContentEncryptionAes256Gcm(key)
        return self
    }
    
    public func aes256gcm(_ key: Data, _ iv: Data) -> JweEncryptionPerformer {
        contentEncryption = ContentEncryptionAes256Gcm(key, iv)
        return self
    }
    
    public func perform() throws -> String {
        let contentEncryption = self.contentEncryption!
        let keyManagementAlgorithm = self.keyManagementAlgorithm!
        
        let keyData = keyManagementAlgorithm.getEncryptedKey(contentEncryption.keyData)
        let keyHeader = keyManagementAlgorithm.algorithmHeader
        
        let dataHeader = contentEncryption.encryptionMethodHeader
        
        let joseHeaderData = [
            "alg": keyHeader,
            "enc": dataHeader
        ]
        
        let joseHeader = try base64urlencode(JSONSerialization.data(withJSONObject: joseHeaderData))
        
        let aad = joseHeader.data(using: String.Encoding.ascii)!
        
        //? compress???
        let (encrypted, tag) = try contentEncryption.encrypt(textProvider.plaintext, aad)
        
        print ("DATA::: " + encrypted.flatMap { i in String(format: "%02x", i) }.joined(separator:" "))
        print ("TAG:::: " + tag.flatMap {i in String(format: "%02x", i)}.joined(separator:" "))
        
        let jweEncryptedKey = base64urlencode(keyData)
        let initializationVector = base64urlencode(contentEncryption.iv)
        let ciphertext = base64urlencode(encrypted)
        let authenticationTag = base64urlencode(tag)
        
        return "\(joseHeader).\(jweEncryptedKey).\(initializationVector).\(ciphertext).\(authenticationTag)"
    }
}


			
