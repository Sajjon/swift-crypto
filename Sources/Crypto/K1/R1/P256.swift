//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-04.
//

import Foundation

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
public typealias P256 = SECP256R1
#endif // Linux or !SwiftPM
