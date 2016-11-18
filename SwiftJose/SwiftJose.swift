//
//  SwiftJose.swift
//  SwiftJose
//
//  Created by rmtmckenzie on 16/11/2016.
//  Copyright © 2016 rmtmckenzie. All rights reserved.
//

import Foundation
import SwCrypt


struct JwConstants {
    static let tagLength = 16
}


public enum JwError: Error {
    case tagMismatch(expectedTag: Data, calculatedTag: Data)
    case invalidSectionCount(expectedCount: Int, actualCount: Int)
    case jsonDecodeProblem()
    case unsupportedDecryptionAlgorithm(alg: String)
    case unsupportedDecryptionEncryptionMethod(enc: String)
}

public protocol PlaintextProvider {
    var plaintext: String { get }
}

public class SwiftJoseBuilder : PlaintextProvider {
    public var plaintext : String
    
    public init(_ string : String) {
        plaintext = string
    }
    
    public func encrypt() -> JweEncryptionKeyManagement {
        return SwiftJweBuilder(self)
    }
}

public protocol TokenProvider {
    var token: String { get }
}

public class SwiftJwParser: TokenProvider {
    public var token: String
    
    public init(_ string : String) {
        token = string
    }
    
    public func decrypt() -> JweDecryptionKeyManagement {
        return SwiftJweParser(self)
    }
}

public protocol JweDecryptionKeyManagement {
    func direct() -> JweDirectContentDecryption
}

public protocol JweDirectContentDecryption {
    func aes256(_ key: Data) -> JweDecryptionPerformer
}

public protocol JweEncryptionKeyManagement {
    func direct() -> JweEncryptionContentEncryption
}

public protocol JweEncryptionContentEncryption {
    func aes256gcm(_ key: Data) -> JweEncryptionPerformer
    func aes256gcm(_ key: Data, _ iv: Data) -> JweEncryptionPerformer
}

public protocol JweEncryptionPerformer {
    func perform() throws -> String
}

public protocol JweDecryptionPerformer {
    func perform() throws -> String
}
