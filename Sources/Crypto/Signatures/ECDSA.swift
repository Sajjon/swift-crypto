//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
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
import Foundation
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

protocol ECDSASignatureProtocol {
    init<D: DataProtocol>(rawRepresentation: D) throws
    init<D: DataProtocol>(derRepresentation: D) throws
    var derRepresentation: Data { get }
    var rawRepresentation: Data { get }
}

protocol NISTECDSASignature: ECDSASignatureProtocol {}
protocol SECGECDSASignature: ECDSASignatureProtocol {}

protocol ECSigning {
    associatedtype PublicKey: EllipticCurvePublicKey & DataValidator & DigestValidator
    associatedtype PrivateKey: EllipticCurvePrivateKey & Signer
    associatedtype ECDSASignature: ECDSASignatureProtocol
}

protocol NISTSigning: ECSigning where PublicKey: NISTECPublicKey, PrivateKey: NISTECPrivateKey, ECDSASignature: NISTECDSASignature {}

protocol SECGSigning: ECSigning where PublicKey: SECGECPublicKey, PrivateKey: SECGECPrivateKey, ECDSASignature: SECGECDSASignature {}



// NIST

extension SECP256R1.Signing.ECDSASignature: NISTECDSASignature {}
// extension SECP256R1.Signing.PublicKey: NISTECPublicKey {}
// extension SECP256R1.Signing.PrivateKey: NISTECPrivateKey {}
extension SECP256R1.Signing: NISTSigning {}


extension P384.Signing.ECDSASignature: NISTECDSASignature {}
// extension P384.Signing.PublicKey: NISTECPublicKey {}
// extension P384.Signing.PrivateKey: NISTECPrivateKey {}
extension P384.Signing: NISTSigning {}


extension P521.Signing.ECDSASignature: NISTECDSASignature {}
// extension P521.Signing.PublicKey: NISTECPublicKey {}
// extension P521.Signing.PrivateKey: NISTECPrivateKey {}
extension P521.Signing: NISTSigning {}



// SECG

// TODO
// extension SECP256K1.Signing.ECDSASignature: SECGECDSASignature {}
// extension SECP256K1.Signing.PublicKey: SECGECPublicKey {}
// extension SECP256K1.Signing.PrivateKey: SECGECPrivateKey {}
// extension SECP256K1.Signing: SECGSigning {}





// MARK: - SECP256R1 + Signing
/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension SECP256R1.Signing {
    public struct ECDSASignature: ContiguousBytes, ECDSASignatureProtocol {
        /// Returns the raw signature.
        /// The raw signature format for ECDSA is r || s
        public var rawRepresentation: Data

        /// Initializes ECDSASignature from the raw representation.
        /// The raw signature format for ECDSA is r || s
        /// As defined in https://tools.ietf.org/html/rfc4754
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * SECP256R1.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * SECP256R1.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Initializes ECDSASignature from the DER representation.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            let parsed = try ASN1.parse(Array(derRepresentation))
            let signature = try ASN1.ECDSASignature<ArraySlice<UInt8>>(asn1Encoded: parsed)

            let coordinateByteCount = SECP256R1.CurveDetails.coordinateByteCount

            guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            // r and s must be padded out to the coordinate byte count.
            var raw = Data()
            raw.reserveCapacity(2 * SECP256R1.CurveDetails.coordinateByteCount)

            raw.append(contentsOf: repeatElement(0, count: SECP256R1.CurveDetails.coordinateByteCount - signature.r.count))
            raw.append(contentsOf: signature.r)
            raw.append(contentsOf: repeatElement(0, count: SECP256R1.CurveDetails.coordinateByteCount - signature.s.count))
            raw.append(contentsOf: signature.s)

            self.rawRepresentation = raw
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A DER-encoded representation of the signature
        public var derRepresentation: Data {
            let raw = rawRepresentation
            let half = raw.count / 2
            let r = Array(raw.prefix(upTo: half))[...]
            let s = Array(raw.suffix(from: half))[...]

            let sig = ASN1.ECDSASignature(r: r, s: s)
            var serializer = ASN1.Serializer()
            try! serializer.serialize(sig)
            return Data(serializer.serializedBytes)
        }
    }
}

extension SECP256R1.Signing: ECSigning {}

// MARK: - SECP256R1 + PrivateKey
extension SECP256R1.Signing.PrivateKey: DigestSigner {
    ///  Generates an ECDSA signature over the SECP256R1 elliptic curve.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D) throws -> SECP256R1.Signing.ECDSASignature {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSignature(for: digest)
        #else
        return try self.openSSLSignature(for: digest)
        #endif
    }
 }

 extension SECP256R1.Signing.PrivateKey: Signer {
    /// Generates an ECDSA signature over the SECP256R1 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> SECP256R1.Signing.ECDSASignature {
        return try self.signature(for: SHA256.hash(data: data))
    }
 }
extension SECP256R1.Signing.PublicKey: DigestValidator {
    /// Verifies an ECDSA signature over the SECP256R1 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: SECP256R1.Signing.ECDSASignature, for digest: D) -> Bool {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return self.coreCryptoIsValidSignature(signature, for: digest)
        #else
        return self.openSSLIsValidSignature(signature, for: digest)
        #endif
    }
}

extension SECP256R1.Signing.PublicKey: DataValidator {
    /// Verifies an ECDSA signature over the SECP256R1 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: SECP256R1.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA256.hash(data: data))
    }
 }

// MARK: - P384 + Signing
/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension P384.Signing {
    public struct ECDSASignature: ContiguousBytes, ECDSASignatureProtocol {
        /// Returns the raw signature.
        /// The raw signature format for ECDSA is r || s
        public var rawRepresentation: Data

        /// Initializes ECDSASignature from the raw representation.
        /// The raw signature format for ECDSA is r || s
        /// As defined in https://tools.ietf.org/html/rfc4754
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * P384.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * P384.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Initializes ECDSASignature from the DER representation.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            let parsed = try ASN1.parse(Array(derRepresentation))
            let signature = try ASN1.ECDSASignature<ArraySlice<UInt8>>(asn1Encoded: parsed)

            let coordinateByteCount = P384.CurveDetails.coordinateByteCount

            guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            // r and s must be padded out to the coordinate byte count.
            var raw = Data()
            raw.reserveCapacity(2 * P384.CurveDetails.coordinateByteCount)

            raw.append(contentsOf: repeatElement(0, count: P384.CurveDetails.coordinateByteCount - signature.r.count))
            raw.append(contentsOf: signature.r)
            raw.append(contentsOf: repeatElement(0, count: P384.CurveDetails.coordinateByteCount - signature.s.count))
            raw.append(contentsOf: signature.s)

            self.rawRepresentation = raw
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A DER-encoded representation of the signature
        public var derRepresentation: Data {
            let raw = rawRepresentation
            let half = raw.count / 2
            let r = Array(raw.prefix(upTo: half))[...]
            let s = Array(raw.suffix(from: half))[...]

            let sig = ASN1.ECDSASignature(r: r, s: s)
            var serializer = ASN1.Serializer()
            try! serializer.serialize(sig)
            return Data(serializer.serializedBytes)
        }
    }
}

extension P384.Signing: ECSigning {}

// MARK: - P384 + PrivateKey
extension P384.Signing.PrivateKey: DigestSigner {
    ///  Generates an ECDSA signature over the P384 elliptic curve.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D) throws -> P384.Signing.ECDSASignature {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSignature(for: digest)
        #else
        return try self.openSSLSignature(for: digest)
        #endif
    }
 }

 extension P384.Signing.PrivateKey: Signer {
    /// Generates an ECDSA signature over the P384 elliptic curve.
    /// SHA384 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> P384.Signing.ECDSASignature {
        return try self.signature(for: SHA384.hash(data: data))
    }
 }
extension P384.Signing.PublicKey: DigestValidator {
    /// Verifies an ECDSA signature over the P384 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: P384.Signing.ECDSASignature, for digest: D) -> Bool {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return self.coreCryptoIsValidSignature(signature, for: digest)
        #else
        return self.openSSLIsValidSignature(signature, for: digest)
        #endif
    }
}

extension P384.Signing.PublicKey: DataValidator {
    /// Verifies an ECDSA signature over the P384 elliptic curve.
    /// SHA384 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: P384.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA384.hash(data: data))
    }
 }

// MARK: - P521 + Signing
/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension P521.Signing {
    public struct ECDSASignature: ContiguousBytes, ECDSASignatureProtocol {
        /// Returns the raw signature.
        /// The raw signature format for ECDSA is r || s
        public var rawRepresentation: Data

        /// Initializes ECDSASignature from the raw representation.
        /// The raw signature format for ECDSA is r || s
        /// As defined in https://tools.ietf.org/html/rfc4754
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * P521.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * P521.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Initializes ECDSASignature from the DER representation.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            let parsed = try ASN1.parse(Array(derRepresentation))
            let signature = try ASN1.ECDSASignature<ArraySlice<UInt8>>(asn1Encoded: parsed)

            let coordinateByteCount = P521.CurveDetails.coordinateByteCount

            guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            // r and s must be padded out to the coordinate byte count.
            var raw = Data()
            raw.reserveCapacity(2 * P521.CurveDetails.coordinateByteCount)

            raw.append(contentsOf: repeatElement(0, count: P521.CurveDetails.coordinateByteCount - signature.r.count))
            raw.append(contentsOf: signature.r)
            raw.append(contentsOf: repeatElement(0, count: P521.CurveDetails.coordinateByteCount - signature.s.count))
            raw.append(contentsOf: signature.s)

            self.rawRepresentation = raw
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A DER-encoded representation of the signature
        public var derRepresentation: Data {
            let raw = rawRepresentation
            let half = raw.count / 2
            let r = Array(raw.prefix(upTo: half))[...]
            let s = Array(raw.suffix(from: half))[...]

            let sig = ASN1.ECDSASignature(r: r, s: s)
            var serializer = ASN1.Serializer()
            try! serializer.serialize(sig)
            return Data(serializer.serializedBytes)
        }
    }
}

extension P521.Signing: ECSigning {}

// MARK: - P521 + PrivateKey
extension P521.Signing.PrivateKey: DigestSigner {
    ///  Generates an ECDSA signature over the P521 elliptic curve.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D) throws -> P521.Signing.ECDSASignature {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSignature(for: digest)
        #else
        return try self.openSSLSignature(for: digest)
        #endif
    }
 }

 extension P521.Signing.PrivateKey: Signer {
    /// Generates an ECDSA signature over the P521 elliptic curve.
    /// SHA512 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> P521.Signing.ECDSASignature {
        return try self.signature(for: SHA512.hash(data: data))
    }
 }
extension P521.Signing.PublicKey: DigestValidator {
    /// Verifies an ECDSA signature over the P521 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: P521.Signing.ECDSASignature, for digest: D) -> Bool {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return self.coreCryptoIsValidSignature(signature, for: digest)
        #else
        return self.openSSLIsValidSignature(signature, for: digest)
        #endif
    }
}

extension P521.Signing.PublicKey: DataValidator {
    /// Verifies an ECDSA signature over the P521 elliptic curve.
    /// SHA512 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: P521.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA512.hash(data: data))
    }
 }

// MARK: - SECP256K1 + Signing
/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension SECP256K1.Signing {
    public struct ECDSASignature: ContiguousBytes, ECDSASignatureProtocol {
        /// Returns the raw signature.
        /// The raw signature format for ECDSA is r || s
        public var rawRepresentation: Data

        /// Initializes ECDSASignature from the raw representation.
        /// The raw signature format for ECDSA is r || s
        /// As defined in https://tools.ietf.org/html/rfc4754
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * SECP256K1.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * SECP256K1.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Initializes ECDSASignature from the DER representation.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            let parsed = try ASN1.parse(Array(derRepresentation))
            let signature = try ASN1.ECDSASignature<ArraySlice<UInt8>>(asn1Encoded: parsed)

            let coordinateByteCount = SECP256K1.CurveDetails.coordinateByteCount

            guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            // r and s must be padded out to the coordinate byte count.
            var raw = Data()
            raw.reserveCapacity(2 * SECP256K1.CurveDetails.coordinateByteCount)

            raw.append(contentsOf: repeatElement(0, count: SECP256K1.CurveDetails.coordinateByteCount - signature.r.count))
            raw.append(contentsOf: signature.r)
            raw.append(contentsOf: repeatElement(0, count: SECP256K1.CurveDetails.coordinateByteCount - signature.s.count))
            raw.append(contentsOf: signature.s)

            self.rawRepresentation = raw
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A DER-encoded representation of the signature
        public var derRepresentation: Data {
            let raw = rawRepresentation
            let half = raw.count / 2
            let r = Array(raw.prefix(upTo: half))[...]
            let s = Array(raw.suffix(from: half))[...]

            let sig = ASN1.ECDSASignature(r: r, s: s)
            var serializer = ASN1.Serializer()
            try! serializer.serialize(sig)
            return Data(serializer.serializedBytes)
        }
    }
}

extension SECP256K1.Signing: ECSigning {}

// MARK: - SECP256K1 + PrivateKey
extension SECP256K1.Signing.PrivateKey: DigestSigner {
    ///  Generates an ECDSA signature over the SECP256K1 elliptic curve.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D) throws -> SECP256K1.Signing.ECDSASignature {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSignature(for: digest)
        #else
        return try self.openSSLSignature(for: digest)
        #endif
    }
 }

 extension SECP256K1.Signing.PrivateKey: Signer {
    /// Generates an ECDSA signature over the SECP256K1 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> SECP256K1.Signing.ECDSASignature {
        return try self.signature(for: SHA256.hash(data: data))
    }
 }
extension SECP256K1.Signing.PublicKey: DigestValidator {
    /// Verifies an ECDSA signature over the SECP256K1 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: SECP256K1.Signing.ECDSASignature, for digest: D) -> Bool {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return self.coreCryptoIsValidSignature(signature, for: digest)
        #else
        return self.openSSLIsValidSignature(signature, for: digest)
        #endif
    }
}

extension SECP256K1.Signing.PublicKey: DataValidator {
    /// Verifies an ECDSA signature over the SECP256K1 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: SECP256K1.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA256.hash(data: data))
    }
 }


#endif // Linux or !SwiftPM
