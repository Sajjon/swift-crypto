//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-04.
//

import Foundation

#if (!CRYPTO_IN_SWIFTPM || CRYPTO_IN_SWIFTPM_FORCE_BUILD_API)
public typealias P256 = SECP256R1
#endif
