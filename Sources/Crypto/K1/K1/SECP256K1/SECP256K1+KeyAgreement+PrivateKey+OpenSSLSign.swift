//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-11.
//

import Foundation

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// NOOP
#else

extension SECP256K1.Signing.PrivateKey {
    func openSSLSignature<D: Digest>(for digest: D) throws -> SECP256K1.Signing.ECDSASignature {
//        let baseSignature = try self.impl.key.sign(digest: digest)
//        return try .init(rawRepresentation: Data(rawSignature: baseSignature, over: SECP256R1.CurveDetails.self))
        todoK1()
    }
}

#endif


