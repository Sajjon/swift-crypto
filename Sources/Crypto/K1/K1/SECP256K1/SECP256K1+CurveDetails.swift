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
protocol EllipticCurve {
    @inlinable
    static var coordinateByteCount: Int { get }
}

@usableFromInline
protocol SECGEllipticCurve: EllipticCurve {}

extension SECP256K1 {
    @usableFromInline
    struct CurveDetails: SECGEllipticCurve {
        @inlinable
        static var coordinateByteCount: Int {
            todoK1()
        }
    }
}

#endif





