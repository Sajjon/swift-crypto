//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2021-04-11.
//

import Foundation

public func todoK1(
    _ message: String = "",
    file: StaticString = #file,
    line: UInt = #line
) -> Never {
    let messageOrEmpty = message.map({ m in " (\(m))" })
    fatalError("Implement support for secp256k1 here\(messageOrEmpty): line: #\(line) in file: \(file)")
}
