import * as Frooky from 'frooky'

// ============================================================================
// EXAMPLE 1: Swift method with mangled symbol
// ============================================================================
const userDefaultsHook: Frooky.SwiftHook = {
  methods: [
    '_$s10Foundation12UserDefaultsC3set_6forKeyySo8NSObjectC_SStF'
  ],
  stackTraceLimit: 5
}

// ============================================================================
// EXAMPLE 2: Swift FileManager method
// ============================================================================
const fileManagerHook: Frooky.SwiftHook = {
  methods: [
    '_$s10Foundation11FileManagerC8contentsAtPath_10FoundationAA4DataVSgSS_tF'
  ]
}

// ============================================================================
// EXAMPLE 3: Swift Keychain wrapper
// ============================================================================
const keychainHook: Frooky.SwiftHook = {
  methods: [
    '_$s8Security12KeychainItemC4save_SbSS_SStKF'
  ],
  debug: true
}

// ============================================================================
// EXAMPLE 4: Multiple Swift methods
// ============================================================================
const multipleSwiftHook: Frooky.SwiftHook = {
  methods: [
    '_$s5MyApp14NetworkManagerC11sendRequestyyF',
    '_$s5MyApp14NetworkManagerC15receiveResponseySSSgAA0D0VF',
    '_$s5MyApp14NetworkManagerC12handleErrorsyySo7NSErrorCF'
  ],
  stackTraceLimit: 10
}

// ============================================================================
// EXAMPLE 5: Swift method with stack trace filtering
// ============================================================================
const filteredSwiftHook: Frooky.SwiftHook = {
  methods: [
    '_$s5MyApp15CryptoUtilitiesC7encryptySS10Foundation4DataVF'
  ],
  stackTraceFilter: ['^Foundation\\.', '^UIKit\\.'],
  debug: true
}

export { 
  userDefaultsHook, 
  fileManagerHook, 
  keychainHook,
  multipleSwiftHook,
  filteredSwiftHook
}
