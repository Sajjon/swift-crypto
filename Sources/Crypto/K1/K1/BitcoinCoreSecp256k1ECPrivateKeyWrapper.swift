//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-11.
//

import Foundation

/// A simple wrapper for an EC_KEY pointer for a private key. This manages the lifetime of that pointer and
/// allows some helper operations.
@usableFromInline
class BitcoinCoreSecp256k1ECPrivateKeyWrapper<Curve: SECGEllipticCurve> {


    @usableFromInline
    var key: OpaquePointer

    init(compactRepresentable: Bool) throws {
//        // We cannot handle allocation failure.
//        let group = Curve.group
//        self.key = try! group.makeUnsafeOwnedECKey()
//
//        // If we've been asked to generate a compact representable key, we need to try a few times. This loop shouldn't
//        // execute more than 100 times: if it does, we'll crash because something bad is happening.
//        for _ in 0 ..< 100 {
//            // We generate FIPS compliant keys to match the behaviour of CryptoKit on Apple platforms.
//            guard CCryptoBoringSSL_EC_KEY_generate_key(self.key) != 0 else {
//                throw CryptoKitError.internalBoringSSLError()
//            }
//
//            // We want to generate FIPS compliant keys. If this isn't, loop around again.
//            if CCryptoBoringSSL_EC_KEY_check_fips(self.key) == 0 {
//                continue
//            }
//
//            if !compactRepresentable || _isCompactRepresentable(group: group, publicKeyPoint: self.publicKeyPoint) {
//                return
//            }
//        }
//        fatalError("Looped more than 100 times trying to generate a key")
        
        todoK1()
    }

    init<Bytes: ContiguousBytes>(x963Representation bytes: Bytes) throws {
//        // Before we do anything, we validate that the x963 representation has the right number of bytes.
//        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
//        // This brings our behaviour into line with CryptoKit
//        let group = Curve.group
//        let length = bytes.withUnsafeBytes { $0.count }
//        guard length == (group.coordinateByteCount * 3) + 1 else {
//            throw CryptoKitError.incorrectParameterSize
//        }
//
//        self.key = try group.makeUnsafeOwnedECKey()
//
//        // First, try to grab the numbers.
//        var (x, y, k) = try bytes.readx963PrivateNumbers()
//
//        // Then we set the private key first, then the public key. In this order, BoringSSL will check the key
//        // validity for us.
//        try self.setPrivateKey(k)
//        try self.setPublicKey(x: &x, y: &y)
        
        todoK1()
    }

    init<Bytes: ContiguousBytes>(rawRepresentation bytes: Bytes) throws {
//        let group = Curve.group
//
//        // Before we do anything, we validate that the raw representation has the right number of bytes.
//        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
//        // This brings our behaviour into line with CryptoKit
//        let length = bytes.withUnsafeBytes { $0.count }
//        guard length == group.coordinateByteCount else {
//            throw CryptoKitError.incorrectParameterSize
//        }
//
//        self.key = try group.makeUnsafeOwnedECKey()
//
//        // The raw representation is just the bytes that make up k.
//        let k = try ArbitraryPrecisionInteger(bytes: bytes)
//
//        // Begin by setting the private key.
//        try self.setPrivateKey(k)
//
//        // Now calculate the public one and set it.
//        let point = try EllipticCurvePoint(multiplying: k, on: group)
//        try self.setPublicKey(point: point)
        todoK1()
    }

    func setPrivateKey(_ keyScalar: ArbitraryPrecisionInteger) throws {
//        try keyScalar.withUnsafeBignumPointer { bigNum in
//            guard CCryptoBoringSSL_EC_KEY_set_private_key(self.key, bigNum) != 0 else {
//                throw CryptoKitError.internalBoringSSLError()
//            }
//        }
        todoK1()
    }

    func setPublicKey(x: inout ArbitraryPrecisionInteger, y: inout ArbitraryPrecisionInteger) throws {
//        try x.withUnsafeMutableBignumPointer { xPointer in
//            try y.withUnsafeMutableBignumPointer { yPointer in
//                // This function is missing some const declarations here, which is why we need the bignums inout.
//                // If that gets fixed, we can clean this function up.
//                guard CCryptoBoringSSL_EC_KEY_set_public_key_affine_coordinates(self.key, xPointer, yPointer) != 0 else {
//                    throw CryptoKitError.internalBoringSSLError()
//                }
//            }
//        }
        todoK1()
    }

    func setPublicKey(point: EllipticCurvePoint) throws {
//        try point.withPointPointer { ecPointer in
//            guard CCryptoBoringSSL_EC_KEY_set_public_key(self.key, ecPointer) != 0 else {
//                throw CryptoKitError.internalBoringSSLError()
//            }
//        }
        todoK1()
    }

    var publicKey: BitcoinCoreSecp256k1ECPublicKeyWrapper<Curve> {
//        // This is a weird little trick we can do here: because EC_KEY is both private and public depending on
//        // its internal state, we can just vend a pointer to ourself and this will work.
//        return try! BoringSSLECPublicKeyWrapper(unsafeTakingOwnership: CCryptoBoringSSL_EC_KEY_dup(self.key))
        todoK1()
    }

    @usableFromInline
    var publicKeyPoint: EllipticCurvePoint {
//        return try! EllipticCurvePoint(copying: CCryptoBoringSSL_EC_KEY_get0_public_key(self.key)!, on: Curve.group)
        todoK1()
    }

    @usableFromInline
    var privateKeyScalar: ArbitraryPrecisionInteger {
//        return try! ArbitraryPrecisionInteger(copying: CCryptoBoringSSL_EC_KEY_get0_private_key(self.key)!)
        todoK1()
    }

    @inlinable
    var rawRepresentation: Data {
//        // The raw representation is just the bytes that make up k. This try! should only fire if we have internal
//        // consistency errors.
//        var bytes = Data()
//        bytes.reserveCapacity(Curve.group.coordinateByteCount)
//        try! bytes.append(bytesOf: self.privateKeyScalar, paddedToSize: Curve.group.coordinateByteCount)
//        return bytes
        todoK1()
    }

    @inlinable
    var x963Representation: Data {
//        // The x9.63 private key format is a discriminator byte (0x4) concatenated with the X and Y points
//        // of the public key, and the K value of the secret scalar. Let's load that in.
//        let group = Curve.group
//        let pointByteCount = group.coordinateByteCount
//        let privateKey = self.privateKeyScalar
//        let (x, y) = try! self.publicKeyPoint.affineCoordinates(group: group)
//
//        var bytes = Data()
//        bytes.reserveCapacity(1 + (group.coordinateByteCount * 3))
//
//        // These try!s should only trigger in the case of internal consistency errors.
//        bytes.append(0x4)
//        try! bytes.append(bytesOf: x, paddedToSize: pointByteCount)
//        try! bytes.append(bytesOf: y, paddedToSize: pointByteCount)
//        try! bytes.append(bytesOf: privateKey, paddedToSize: pointByteCount)
//
//        return bytes
        todoK1()
    }

    func keyExchange(publicKey: BitcoinCoreSecp256k1ECPublicKeyWrapper<Curve>) throws -> SecureBytes {
//        let pubKeyPoint = publicKey.publicKeyPoint
//        let outputSize = Curve.group.coordinateByteCount
//
//        return try SecureBytes(unsafeUninitializedCapacity: outputSize) { secretPtr, secretSize in
//            let rc = pubKeyPoint.withPointPointer { pointPtr in
//                CCryptoBoringSSL_ECDH_compute_key(secretPtr.baseAddress, secretPtr.count, pointPtr, self.key, nil)
//            }
//
//            if rc == -1 {
//                throw CryptoKitError.internalBoringSSLError()
//            }
//            precondition(rc == outputSize, "Unexpectedly short secret.")
//            secretSize = Int(rc)
//        }
        todoK1()
    }

    func sign<D: Digest>(digest: D) throws -> ECDSASignature {
//        let optionalRawSignature: UnsafeMutablePointer<ECDSA_SIG>? = digest.withUnsafeBytes { digestPtr in
//            CCryptoBoringSSLShims_ECDSA_do_sign(digestPtr.baseAddress, digestPtr.count, self.key)
//        }
//        guard let rawSignature = optionalRawSignature else {
//            throw CryptoKitError.internalBoringSSLError()
//        }
//
//        return ECDSASignature(takingOwnershipOf: rawSignature)
        todoK1()
    }

    deinit {
//        CCryptoBoringSSL_EC_KEY_free(self.key)
        todoK1()
    }
}

