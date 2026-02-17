import * as Frooky from 'frooky'

// ============================================================================
// EXAMPLE 1: Simple Objective-C instance method
// ============================================================================
const userDefaultsObjCHook: Frooky.ObjectiveCHook = {
  objClass: 'NSUserDefaults',
  methods: [
    {
      name: '- setObject:forKey:',
      params: [
        { type: '(id)', name: 'value' },
        { type: '(NSString *)', name: 'key' }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 2: NSData write to file with return type
// ============================================================================
const nsDataHook: Frooky.ObjectiveCHook = {
  objClass: 'NSData',
  methods: [
    {
      name: '- writeToFile:atomically:',
      returnType: '(BOOL)',
      params: [
        { type: '(NSString *)', name: 'path' },
        { type: '(BOOL)', name: 'useAuxiliaryFile' }
      ]
    }
  ],
  stackTraceLimit: 8
}

// ============================================================================
// EXAMPLE 3: Objective-C class method
// ============================================================================
const urlHook: Frooky.ObjectiveCHook = {
  objClass: 'NSURL',
  methods: [
    {
      name: '+ fileURLWithFileSystemRepresentation:isDirectory:relativeToURL:',
      returnType: '(NSURL *)',
      params: [
        { type: '(const char *)', name: 'path' },
        { type: '(BOOL)', name: 'isDir' },
        { type: '(NSURL *)', name: 'baseURL' }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 4: LAContext biometry method (no params)
// ============================================================================
const laContextHook: Frooky.ObjectiveCHook = {
  objClass: 'LAContext',
  methods: [
    {
      name: '- invalidate'
    }
  ]
}

// ============================================================================
// EXAMPLE 5: Multiple methods in same class
// ============================================================================
const keychainHook: Frooky.ObjectiveCHook = {
  objClass: 'LAPrivateKey',
  methods: [
    {
      name: '- decryptData:secKeyAlgorithm:completion:',
      params: [
        { type: '(NSData *)', name: 'data' },
        { type: '(SecKeyAlgorithm)', name: 'algorithm' },
        { 
          type: '(void (^)(NSData *, NSError *))', 
          name: 'handler',
          decoder: 'LaPlaintextDecoder'  // Custom decoder for async callback
        }
      ]
    },
    {
      name: '- signData:secKeyAlgorithm:completion:',
      params: [
        { type: '(NSData *)', name: 'data' },
        { type: '(SecKeyAlgorithm)', name: 'algorithm' },
        { type: '(void (^)(NSData *, NSError *))', name: 'handler' }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 6: CoreData save with output parameter
// ============================================================================
const coreDataHook: Frooky.ObjectiveCHook = {
  objClass: 'NSManagedObjectContext',
  methods: [
    {
      name: '- save:',
      returnType: '(BOOL)',
      params: [
        { 
          type: '(NSError **)', 
          name: 'error',
          decodeAt: 'exit'  // Decode error after method execution
        }
      ]
    }
  ],
  debug: true
}

// ============================================================================
// EXAMPLE 7: Network request with stack trace filtering
// ============================================================================
const urlSessionHook: Frooky.ObjectiveCHook = {
  objClass: 'NSURLSession',
  methods: [
    {
      name: '- dataTaskWithRequest:completionHandler:',
      returnType: '(NSURLSessionDataTask *)',
      params: [
        { type: '(NSURLRequest *)', name: 'request' },
        { type: '(void (^)(NSData *, NSURLResponse *, NSError *))', name: 'completionHandler' }
      ]
    }
  ],
  stackTraceFilter: ['^libsystem_', '^Foundation']
}

// ============================================================================
// EXAMPLE 8: Method with both entry and exit decoding
// ============================================================================
const dataProcessingHook: Frooky.ObjectiveCHook = {
  objClass: 'NSMutableData',
  methods: [
    {
      name: '- appendData:',
      params: [
        { 
          type: '(NSData *)', 
          name: 'data',
          decodeAt: 'both'  // Capture data before and after
        }
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
