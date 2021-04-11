//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-11.
//

import Foundation

/// A simple wrapper for an EC_KEY pointer for a public key. This manages the lifetime of that pointer and
/// allows some helper operations.
@usableFromInline
class BitcoinCoreSecp256k1ECPublicKeyWrapper<Curve: SECGEllipticCurve> {
    @usableFromInline
    var key: OpaquePointer

    init<Bytes: ContiguousBytes>(compactRepresentation bytes: Bytes) throws {
//        let group = Curve.group
//
//        // Before we do anything, we validate that the compact representation has the right number of bytes.
//        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
//        // This brings our behaviour into line with CryptoKit
//        let length = bytes.withUnsafeBytes { $0.count }
//        guard length == group.coordinateByteCount else {
//            throw CryptoKitError.incorrectParameterSize
//        }
//
//        self.key = try group.makeUnsafeOwnedECKey()
//
//        // The compact representation is simply the X coordinate: deserializing then requires us to do a little math,
//        // as discussed in https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html#rfc.section.4.1.
//        var x = try ArbitraryPrecisionInteger(bytes: bytes)
//
//        // We now need to solve the curve equation in Weierstrass form. This form is y² = x³ + ax + b. We need a and b.
//        // We also need a finite field context, which means we need the order of the underlying prime field. We call that
//        // p, for later.
//        let (p, a, b) = group.weierstrassCoefficients
//        let context = try FiniteFieldArithmeticContext(fieldSize: p)
//        let xCubed = try (context.multiply(context.square(x), x))
//        let ax = try context.multiply(a, x)
//        let ySquared = try context.add(context.add(xCubed, ax), b)
//
//        // We want the positive square root value of y, which conveniently is what we can get. We will call this yPrime.
//        // We then need to calculate y = min(yPrime, p-yPrime) where p is the order of the underlying finite field.
//        let yPrime = try context.positiveSquareRoot(ySquared)
//        var y = min(yPrime, try context.subtract(yPrime, from: p))
//
//        // This is the full set of coordinates. We're done.
//        try self.setPublicKey(x: &x, y: &y)
        todoK1()
    }

    init<Bytes: ContiguousBytes>(x963Representation bytes: Bytes) throws {
        // Before we do anything, we validate that the x963 representation has the right number of bytes.
        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
        // This brings our behaviour into line with CryptoKit
        let group = Curve.group
        let length = bytes.withUnsafeBytes { $0.count }
        guard length == (group.coordinateByteCount * 2) + 1 else {
            throw CryptoKitError.incorrectParameterSize
        }

        self.key = try group.makeUnsafeOwnedECKey()
        var (x, y) = try bytes.readx963PublicNumbers()
        try self.setPublicKey(x: &x, y: &y)
    }

    init<Bytes: ContiguousBytes>(rawRepresentation bytes: Bytes) throws {
//        let group = Curve.group
//
//        // Before we do anything, we validate that the raw representation has the right number of bytes.
//        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
//        // This brings our behaviour into line with CryptoKit
//        let length = bytes.withUnsafeBytes { $0.count }
//        guard length == group.coordinateByteCount * 2 else {
//            throw CryptoKitError.incorrectParameterSize
//        }
//
//        self.key = try group.makeUnsafeOwnedECKey()
//
//        // The raw representation is identical to the x963 representation, without the leading 0x4.
//        var (x, y): (ArbitraryPrecisionInteger, ArbitraryPrecisionInteger) = try bytes.withUnsafeBytes { bytesPtr in
//            try readRawPublicNumbers(copyingBytes: bytesPtr)
//        }
//
//        // Then we set the public key and we're done.
//        try self.setPublicKey(x: &x, y: &y)
        todoK1()
    }

    /// Takes ownership of the pointer. If this throws, ownership of the pointer has not been taken.
    @usableFromInline
    init(unsafeTakingOwnership ownedPointer: OpaquePointer) throws {
//        guard let newKeyGroup = CCryptoBoringSSL_EC_KEY_get0_group(ownedPointer) else {
//            throw CryptoKitError.internalBoringSSLError()
//        }
//        let groupEqual = Curve.group.withUnsafeGroupPointer { ourCurvePointer in
//            CCryptoBoringSSL_EC_GROUP_cmp(newKeyGroup, ourCurvePointer, nil)
//        }
//        guard groupEqual == 0 else {
//            throw CryptoKitError.incorrectParameterSize
//        }
//
//        self.key = ownedPointer
        todoK1()
    }

    @inlinable
    var compactRepresentation: Data? {
//        let group = Curve.group
//        guard _isCompactRepresentable(group: group, publicKeyPoint: self.publicKeyPoint) else {
//            return nil
//        }
//
//        // The compact representation is simply the X coordinate. This try! should only fire on internal consistency
//        // errors.
//        var bytes = Data()
//        bytes.reserveCapacity(group.coordinateByteCount)
//
//        let (x, _) = try! self.publicKeyPoint.affineCoordinates(group: group)
//        try! bytes.append(bytesOf: x, paddedToSize: group.coordinateByteCount)
//        return bytes
        todoK1()
    }

    @inlinable
    var rawRepresentation: Data {
//        // The raw representation is the X coordinate concatenated with the Y coordinate: essentially, it's
//        // the x963 representation without the leading byte.
//        return self.x963Representation.dropFirst()
        todoK1()
    }

    @inlinable
    var x963Representation: Data {
//        // The x963 representation is the X coordinate concatenated with the Y coordinate, prefixed by the byte 0x04.
//        let group = Curve.group
//        let (x, y) = try! self.publicKeyPoint.affineCoordinates(group: group)
//        let pointByteCount = group.coordinateByteCount
//
//        var bytes = Data()
//        bytes.reserveCapacity(1 + (group.coordinateByteCount * 2))
//
//        // These try!s should only trigger on internal consistency errors.
//        bytes.append(0x4)
//        try! bytes.append(bytesOf: x, paddedToSize: pointByteCount)
//        try! bytes.append(bytesOf: y, paddedToSize: pointByteCount)
//
//        return bytes
        todoK1()
    }

    deinit {
//        CCryptoBoringSSL_EC_KEY_free(self.key)
        todoK1()
    }

    @usableFromInline
    var publicKeyPoint: EllipticCurvePoint {
//        return try! EllipticCurvePoint(copying: CCryptoBoringSSL_EC_KEY_get0_public_key(self.key)!, on: Curve.group)
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

    func isValidSignature<D: Digest>(_ signature: ECDSASignature, for digest: D) -> Bool {
//        let rc: CInt = signature.withUnsafeSignaturePointer { signaturePointer in
//            digest.withUnsafeBytes { digestPointer in
//                CCryptoBoringSSLShims_ECDSA_do_verify(digestPointer.baseAddress, digestPointer.count, signaturePointer, self.key)
//            }
//        }
//
//        return rc == 1
        todoK1()
    }
}

