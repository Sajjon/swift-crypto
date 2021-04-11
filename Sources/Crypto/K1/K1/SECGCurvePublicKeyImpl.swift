//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-11.
//

import Foundation

@usableFromInline
struct SECGCurvePublicKeyImpl<Curve: SECGEllipticCurve> {
    @usableFromInline
    var key: BitcoinCoreSecp256k1ECPublicKeyWrapper<Curve>

    init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
        self.key = try BitcoinCoreSecp256k1ECPublicKeyWrapper(compactRepresentation: compactRepresentation)
    }

    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
        self.key = try BitcoinCoreSecp256k1ECPublicKeyWrapper(x963Representation: x963Representation)
    }

    init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
        self.key = try BitcoinCoreSecp256k1ECPublicKeyWrapper(rawRepresentation: rawRepresentation)
    }

    @inlinable
    init(wrapping key: BitcoinCoreSecp256k1ECPublicKeyWrapper<Curve>) {
        self.key = key
    }

    @inlinable
    var compactRepresentation: Data? {
        return self.key.compactRepresentation
    }

    @inlinable
    var rawRepresentation: Data {
        return self.key.rawRepresentation
    }

    @inlinable
    var x963Representation: Data {
        return self.key.x963Representation
    }
}
