import * as Frooky from 'frooky'

// ============================================================================
// EXAMPLE 1: Simple Objective-C instance method
// ============================================================================
const userDefaultsObjCHook: Frooky.ObjectiveCHook = {
  objcClass: 'NSUserDefaults',
  methods: [
    {
      name: '- setObject:forKey:',
      params: [
        ['(id)', 'value'],
        ['(NSString *)', 'key']
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 2: NSData write to file with return type
// ============================================================================
const nsDataHook: Frooky.ObjectiveCHook = {
  objcClass: 'NSData',
  methods: [
    {
      name: '- writeToFile:atomically:',
      returnType: '(BOOL)',
      params: [
        ['(NSString *)', 'path'],
        ['(BOOL)', 'useAuxiliaryFile']
      ]
    }
  ],
  stackTraceLimit: 8
}

// ============================================================================
// EXAMPLE 3: Objective-C class method
// ============================================================================
const urlHook: Frooky.ObjectiveCHook = {
  objcClass: 'NSURL',
  methods: [
    {
      name: '+ fileURLWithFileSystemRepresentation:isDirectory:relativeToURL:',
      returnType: '(NSURL *)',
      params: [
        ['(const char *)', 'path'],
        ['(BOOL)', 'isDir'],
        ['(NSURL *)', 'baseURL']
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 4: LAContext biometry method (no params)
// ============================================================================
const laContextHook: Frooky.ObjectiveCHook = {
  objcClass: 'LAContext',
  methods: [
    '- invalidate'
  ]
}

// ============================================================================
// EXAMPLE 5: Multiple methods in same class
// ============================================================================
const keychainHook: Frooky.ObjectiveCHook = {
  objcClass: 'LAPrivateKey',
  methods: [
    {
      name: '- decryptData:secKeyAlgorithm:completion:',
      params: [
        ['(NSData *)', 'data'],
        ['(SecKeyAlgorithm)', 'algorithm'],
        ['(void (^)(NSData *, NSError *))', 'handler', { decoder: 'LaPlaintextDecoder' }]
      ]
    },
    {
      name: '- signData:secKeyAlgorithm:completion:',
      params: [
        ['(NSData *)', 'data'],
        ['(SecKeyAlgorithm)', 'algorithm'],
        ['(void (^)(NSData *, NSError *))', 'handler']
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 6: CoreData save with output parameter
// ============================================================================
const coreDataHook: Frooky.ObjectiveCHook = {
  objcClass: 'NSManagedObjectContext',
  methods: [
    {
      name: '- save:',
      returnType: '(BOOL)',
      params: [
        ['(NSError **)', 'error', { decodeAt: 'exit' }]
      ]
    }
  ],
  debug: true
}

// ============================================================================
// EXAMPLE 7: Network request with stack trace filtering
// ============================================================================
const urlSessionHook: Frooky.ObjectiveCHook = {
  objcClass: 'NSURLSession',
  methods: [
    {
      name: '- dataTaskWithRequest:completionHandler:',
      returnType: '(NSURLSessionDataTask *)',
      params: [
        ['(NSURLRequest *)', 'request'],
        ['(void (^)(NSData *, NSURLResponse *, NSError *))', 'completionHandler']
      ]
    }
  ],
  stackTraceFilter: ['^libsystem_', '^Foundation']
}

// ============================================================================
// EXAMPLE 8: Method with both entry and exit decoding
// ============================================================================
const dataProcessingHook: Frooky.ObjectiveCHook = {
  objcClass: 'NSMutableData',
  methods: [
    {
      name: '- appendData:',
      params: [
        ['(NSData *)', 'data', { decodeAt: 'both' }]
      ]
    }
  ]
}

export {
  userDefaultsObjCHook,
  nsDataHook,
  urlHook,
  laContextHook,
  keychainHook,
  coreDataHook,
  urlSessionHook,
  dataProcessingHook
}
