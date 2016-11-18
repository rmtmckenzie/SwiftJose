//
//  Base64.swift
//  SwiftJose
//
//  Created by rmtmckenzie on 16/11/2016.
//  Copyright © 2016 rmtmckenzie. All rights reserved.
//

import Foundation


public func base64urlencode(_ data: Data, withoutPadding: Bool = true) -> String {
    return base64encode(data, withoutPadding: withoutPadding)
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
}

func base64encode(_ data: Data, withoutPadding: Bool = false) -> String {
    let encoded = data.base64EncodedString()
    return withoutPadding ? encoded.replacingOccurrences(of: "=", with: "") : encoded
}

func base64urldecode(_ input: String) -> Data? {
    let remainder = input.characters.count % 4

    let ending = remainder > 0 ? String(repeating: "=", count: 4 - remainder) : ""
    
    let base64 = input
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
        + ending
    
    return Data(base64Encoded: base64)
}
