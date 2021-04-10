//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL

extension SECP256R1.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(with publicKeyShare: SECP256R1.KeyAgreement.PublicKey) throws -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}

extension P384.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(with publicKeyShare: P384.KeyAgreement.PublicKey) throws -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}

extension P521.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(with publicKeyShare: P521.KeyAgreement.PublicKey) throws -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}

extension SECP256K1.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(with publicKeyShare: SECP256K1.KeyAgreement.PublicKey) throws -> SharedSecret {
//        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
//        return SharedSecret(ss: key)
        todoK1()
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
