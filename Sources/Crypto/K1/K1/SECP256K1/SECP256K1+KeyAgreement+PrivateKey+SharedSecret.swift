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

extension SECP256K1.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(with publicKeyShare: SECP256K1.KeyAgreement.PublicKey) throws -> SharedSecret {
//        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
//        return SharedSecret(ss: key)
        todoK1()
    }
}

#endif

