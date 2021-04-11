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

@usableFromInline
protocol EllipticCurveGroup {
    var coordinateByteCount: Int { get }
  
    func makeUnsafeOwnedECKey() throws -> OpaquePointer
    
    func withUnsafeGroupPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T

    var order: ArbitraryPrecisionInteger { get }

    var weierstrassCoefficients: (field: ArbitraryPrecisionInteger, a: ArbitraryPrecisionInteger, b: ArbitraryPrecisionInteger) { get }
}


@usableFromInline
protocol EllipticCurve {
    
    associatedtype Group: EllipticCurveGroup
    @inlinable
    static var group: Group { get }
    
    @inlinable
    static var coordinateByteCount: Int { get }
}

extension EllipticCurve {
    @inlinable
    static var coordinateByteCount: Int {
        group.coordinateByteCount
    }
}

@usableFromInline
protocol SECGEllipticCurve: EllipticCurve {
    
}

@usableFromInline
class BitcoinCoreSecp256K1Group: EllipticCurveGroup {
   
    @usableFromInline
    var coordinateByteCount: Int {
        todoK1()
    }
    
    @usableFromInline
    func makeUnsafeOwnedECKey() throws -> OpaquePointer {
        todoK1()
    }
    
    @inlinable
    func withUnsafeGroupPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
//        return try body(self._group)
        todoK1()
    }

    @usableFromInline
    var order: ArbitraryPrecisionInteger {
//        // Groups must have an order.
//        let baseOrder = CCryptoBoringSSL_EC_GROUP_get0_order(self._group)!
//        return try! ArbitraryPrecisionInteger(copying: baseOrder)
        todoK1()
    }

    /// An elliptic curve can be represented in a Weierstrass form: `y² = x³ + ax + b`. This
    /// property provides the values of a and b on the curve.
    @usableFromInline
    var weierstrassCoefficients: (field: ArbitraryPrecisionInteger, a: ArbitraryPrecisionInteger, b: ArbitraryPrecisionInteger) {
//        var field = ArbitraryPrecisionInteger()
//        var a = ArbitraryPrecisionInteger()
//        var b = ArbitraryPrecisionInteger()
//
//        let rc = field.withUnsafeMutableBignumPointer { fieldPtr in
//            a.withUnsafeMutableBignumPointer { aPtr in
//                b.withUnsafeMutableBignumPointer { bPtr in
//                    CCryptoBoringSSL_EC_GROUP_get_curve_GFp(self._group, fieldPtr, aPtr, bPtr, nil)
//                }
//            }
//        }
//        precondition(rc == 1, "Unable to extract curve weierstrass parameters")
//
//        return (field: field, a: a, b: b)
        todoK1()
    }

}

extension SECP256K1 {
    @usableFromInline
    struct CurveDetails: SECGEllipticCurve {
        @inlinable
        static var group: Group {
//            return try! BoringSSLEllipticCurveGroup(.p256)
            todoK1()
        }
        
        @usableFromInline
        typealias Group = BitcoinCoreSecp256K1Group

    }
}

#endif





