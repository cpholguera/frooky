import * as Frooky from 'frooky'

// ============================================================================
// EXAMPLE 1: Simple Objective-C method
// ============================================================================
const userDefaultsObjCHook: Frooky.ObjectiveCHook = {
  objClass: 'NSUserDefaults',
  symbol: '- setObject:forKey:',
  args: [
    { name: 'value', type: 'pointer' },
    { name: 'key', type: 'string' }
  ]
}

// ============================================================================
// EXAMPLE 2: NSData write to file
// ============================================================================
const nsDataHook: Frooky.ObjectiveCHook = {
  objClass: 'NSData',
  symbol: '- writeToFile:atomically:',
  args: [
    { name: 'path', type: 'string' },
    { name: 'useAuxiliaryFile', type: 'bool' },
    { name: 'success', type: 'bool', retValue: true }
  ],
  stackTraceLimit: 8
}

// ============================================================================
// EXAMPLE 3: Keychain operations
// ============================================================================
const secItemHook: Frooky.ObjectiveCHook = {
  objClass: 'SecItemAdd',
  module: 'Security',
  symbol: 'SecItemAdd',
  args: [
    { name: 'attributes', type: 'CFDictionary' },
    { name: 'result', type: 'pointer', direction: 'out' },
    { name: 'status', type: 'int32', retValue: true }
  ]
}

// ============================================================================
// EXAMPLE 4: Network request with multiple args
// ============================================================================
const urlSessionHook: Frooky.ObjectiveCHook = {
  objClass: 'NSURLSession',
  symbol: '- dataTaskWithRequest:completionHandler:',
  args: [
    { name: 'request', type: 'pointer' },
    { name: 'completionHandler', type: 'pointer' },
    { name: 'task', type: 'pointer', retValue: true }
  ],
  stackTraceFilter: ['^libsystem_', '^Foundation']
}

// ============================================================================
// EXAMPLE 5: CoreData save operation
// ============================================================================
const coreDataHook: Frooky.ObjectiveCHook = {
  objClass: 'NSManagedObjectContext',
  symbol: '- save:',
  args: [
    { name: 'error', type: 'pointer', direction: 'out' },
    { name: 'success', type: 'bool', retValue: true }
  ],
  debug: true
}

export { userDefaultsObjCHook, nsDataHook, secItemHook, urlSessionHook, coreDataHook }