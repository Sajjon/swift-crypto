//
//  BridgePrivateKeyTests.swift
//
//
//  Created by Alexander Cyon on 2021-04-09.
//

import Foundation
import XCTest

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// NOOP
#else

@testable import K1

public protocol EllipticCurve: NISTSigning {}

extension SECP256R1: EllipticCurve {}
public extension SECP256R1 {
    typealias PublicKey = Signing.PublicKey
    typealias PrivateKey = Signing.PrivateKey
    typealias ECDSASignature = Signing.ECDSASignature
}

//extension SECP256K1: EllipticCurve {}
//public extension SECP256K1 {
//    typealias PublicKey = Signing.PublicKey
//    typealias PrivateKey = Signing.PrivateKey
//    typealias ECDSASignature = Signing.ECDSASignature
//}

final class BridgePrivateKeyTests: XCTestCase {
    
    /// Private Key WIF example from http://docs.neo.org/en-us/utility/sdk/common.html
    func testSecp256r1PrivateKeyToPublicKey() throws {
        try orFail {
            try doTestPublicKeyFromPrivateKey(
                curve: SECP256R1.self,
                privateKeyHex: "3d40f190da0c18e94db98ec34305113aae7c51b51b6570a8fddaa3a981cd69c3",
                expectedPublicKeyHex: "ed4ab8839c65c65a88f0f288ed9c443f9c5488323e61ed7dbb8edf9be6b1746d3e13be2ffcb19403a761420b1d26af55e265a6f924fe0b7174d4d3654249092f"
            )
        }
    }
    
    func testSecp256r1PrivateKeyToPublicKey2() throws {
        try orFail {
            try doTestPublicKeyFromPrivateKey(
                curve: SECP256R1.self,
                privateKeyHex: "1d6daf1f253f4568030e70108826e729662407eef24d10f98aca7b0f24843115",
                expectedPublicKeyHex: "b14c55ce9e942e7439171ebdffbcffe8ed0c933475aec792b0d48ec1829ea2065598091915effa6f181d3ec8b4374806247081684c822d622dde241288b9f0b4"
            )
        }
    }
    
    // https://boringssl.googlesource.com/boringssl/+/refs/heads/master/third_party/wycheproof_testvectors/ecdsa_secp256r1_sha256_test.txt
    // tcId = 1
    func test_Romeo_SECP256R1Wycheproof() throws {
        let vector = SignatureTestVector.init(
            comment: "Already part of 'ECDSASignatureTest'",
            msg: "313233343030",
            sig: "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1802204cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
            result: "valid",
            flags: [],
            tcId: 1
        )
        
        let key = ECDSAKey(
            uncompressed: "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"
        )
        
        try orFail {
            try doTestVectorAndKey(
                vector: vector,
                key: key,
                curve: SECP256R1.self,
                hashFunction: SHA256.self
            )
        }
    }
    
    
    // https://boringssl.googlesource.com/boringssl/+/refs/heads/master/third_party/wycheproof_testvectors/ecdsa_secp256k1_sha256_test.json
    // tcId = 1
    func test_Kilo_SECP256K1Wycheproof() throws {
        let vector = SignatureTestVector.init(
            comment: "K1 test vector",
            msg: "313233343030",
            sig: "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
            result: "valid",
            flags: [],
            tcId: 1
        )
        
        let key = ECDSAKey(
            uncompressed: "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        )
        
        try orFail {
            XCTFail("uncomment block below")
//            try doTestVectorAndKey(
//                vector: vector,
//                key: key,
//                curve: SECP256K1.self,
//                hashFunction: SHA256.self
//            )
        }
    }
    
}

extension BridgePrivateKeyTests {
    func doTestPublicKeyFromPrivateKey<C: EllipticCurve>(
        curve: C.Type,
        privateKeyHex: String,
        expectedPublicKeyHex: String,
        line: UInt = #line
    ) throws {
        let privateKey = try C.PrivateKey(rawRepresentation: try Data(hexString: privateKeyHex))
        let publicKey = privateKey.publicKey
        XCTAssertEqual(publicKey.rawRepresentation.hexString, expectedPublicKeyHex, line: line)
    }
}

#endif

extension String {
    init(hexEncoding data: Data) {
        self = data.map { byte in
            let s = String(byte, radix: 16)
            switch s.count {
            case 0:
                return "00"
            case 1:
                return "0" + s
            case 2:
                return s
            default:
                fatalError("Weirdly hex encoded byte")
            }
        }.joined()
    }
}
