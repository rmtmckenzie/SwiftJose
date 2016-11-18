//
//  SwiftJoseTests.swift
//  SwiftJoseTests
//
//  Created by rmtmckenzie on 16/11/2016.
//  Copyright © 2016 rmtmckenzie. All rights reserved.
//

import Quick
import Nimble
import SwiftJose


class SwiftJose_Test_Aes_Encrypt: QuickSpec {
    override func spec() {
        describe("SwiftJose") {
            it("returns an encrypted token") {
                // all-zeroes key
                let key = Data(count: 32)
                
                let jwt = try? SwiftJoseBuilder("some text")
                    .encrypt()
                    .direct()
                    .aes256gcm(key, Data(count:16))
                    .perform()
                
                print("JWT:",jwt ?? "??")
            expect(jwt).to(equal("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..AAAAAAAAAAAAAAAAAAAAAA.rDytaBBjW_Po.ym15SFV2lhAn3QlcraJPQg"))
                
            }
        }
    }
}

class SwiftJose_Test_Aes_Decrypt: QuickSpec {
    override func spec() {
        describe("SwiftJose") {
            it("decrypts an encrypted token") {
                // all-zeroes key
                let key = Data(count:32)
                let jwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..O7r5wQPjwKMsToNp.3uF3LiUUAT3yPagMdg.6P8mN5Q8jalrYPBfR0ULqQ"
                let pt = try? SwiftJwParser(jwe)
                    .decrypt()
                    .direct()
                    .aes256(key)
                    .perform()
                
                expect(pt).to(equal("this is a jwt"))
                print("Decrypted:",pt ?? "??")
            }
        }
    }
}

import SwCrypt

class SwiftJose_Test_Aes_EncryptDecrypt: QuickSpec {
    override func spec() {
        describe("SwiftJose") {
            it("encrypts and decrypts a token") {
                let key = CC.generateRandom(16)
                let text = "this is a new jwt"
                
                let jwe = try? SwiftJoseBuilder(text)
                    .encrypt()
                    .direct()
                    .aes256gcm(key)
                    .perform()
                
                print("JWE:", jwe ?? "??")
                
                let pt = try? SwiftJwParser(jwe!)
                    .decrypt()
                    .direct()
                    .aes256(key)
                    .perform()
                
                expect(pt).to(equal(text))
            }
        }
    }
}

