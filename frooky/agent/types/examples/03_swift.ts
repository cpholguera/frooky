import * as Frooky from '../index'

// ============================================================================
// EXAMPLE 1: Swift UserDefaults
// ============================================================================
const userDefaultsHook: Frooky.SwiftHook = {
  swiftClass: 'Foundation.UserDefaults',
  symbol: '_TFC10Foundation12UserDefaults6setKey_forKey_',
  args: [
    { name: 'value', type: 'pointer' },
    { name: 'key', type: 'string' }
  ],
  stackTraceLimit: 5
}

// ============================================================================
// EXAMPLE 2: Swift FileManager with CFData
// ============================================================================
const fileManagerHook: Frooky.SwiftHook = {
  swiftClass: 'Foundation.FileManager',
  symbol: '_TFC10Foundation11FileManager8contentsAtPath_',
  args: [
    { name: 'path', type: 'string' },
    { name: 'data', type: 'CFData', retValue: true }
  ]
}

// ============================================================================
// EXAMPLE 3: Swift Keychain wrapper
// ============================================================================
const keychainHook: Frooky.SwiftHook = {
  swiftClass: 'Security.KeychainItem',
  symbol: '_TFC8Security12KeychainItem4save_',
  args: [
    { name: 'password', type: 'string' },
    { name: 'account', type: 'string' },
    { name: 'service', type: 'string' }
  ],
  debug: true
}


export { userDefaultsHook, fileManagerHook, keychainHook }