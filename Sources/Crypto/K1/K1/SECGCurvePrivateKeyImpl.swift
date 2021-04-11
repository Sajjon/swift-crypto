//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-11.
//

import Foundation

@usableFromInline
struct SECGCurvePrivateKeyImpl<Curve: SECGEllipticCurve> {
    @usableFromInline
    var key: BitcoinCoreSecp256k1ECPrivateKeyWrapper<Curve>

    init(compactRepresentable: Bool = true) {
        self.key = try! BitcoinCoreSecp256k1ECPrivateKeyWrapper(compactRepresentable: compactRepresentable)
    }

    init<Bytes: ContiguousBytes>(x963: Bytes) throws {
        self.key = try BitcoinCoreSecp256k1ECPrivateKeyWrapper(x963Representation: x963)
    }

    init<Bytes: ContiguousBytes>(data: Bytes) throws {
        self.key = try BitcoinCoreSecp256k1ECPrivateKeyWrapper(rawRepresentation: data)
    }

    func publicKey() -> SECGCurvePublicKeyImpl<Curve> {
        return SECGCurvePublicKeyImpl(wrapping: self.key.publicKey)
    }

    var rawRepresentation: Data {
        return self.key.rawRepresentation
    }

    var x963Representation: Data {
        return self.key.x963Representation
    }
}
