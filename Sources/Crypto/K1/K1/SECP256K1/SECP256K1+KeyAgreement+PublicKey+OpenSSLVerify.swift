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

extension SECP256K1.Signing.PublicKey {
    
    func openSSLIsValidSignature<D: Digest>(_ signature: SECP256K1.Signing.ECDSASignature, for digest: D) -> Bool {
//        guard let baseSignature = try? ECDSASignature(rawRepresentation: signature.rawRepresentation) else {
//            // If we can't create a signature, it's not valid.
//            return false
//        }
//
//        return self.impl.key.isValidSignature(baseSignature, for: digest)
        todoK1()
    }
}

#endif
