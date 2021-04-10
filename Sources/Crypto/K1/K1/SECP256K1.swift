//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-04.
//

import Foundation

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// NOOP
#else
public enum SECP256K1 {}

extension ASN1.ASN1ObjectIdentifier.NamedCurves {
    
    /// `secp256k1`, aka `"Bitcoin curve"`, aka `ansip256k1`
    /// http://oid-info.com/get/1.3.132.0.10
    static let secp256k1: ASN1.ASN1ObjectIdentifier = [1, 3, 132, 0, 10]
}
#endif

public func todoK1(
    _ message: String = "",
    file: StaticString = #file,
    line: UInt = #line
) -> Never {
    let messageOrEmpty = message.map({ m in " (\(m))" })
    fatalError("Implement support for secp256k1 here\(messageOrEmpty): line: #\(line) in file: \(file)")
}
