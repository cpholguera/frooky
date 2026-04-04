import * as Frooky from '../types/index'

// ============================================================================
// Simple Objective-C instance method
// Reference: https://developer.apple.com/documentation/foundation/nsmutabledictionary/setobject(_:forkey:)?language=objc
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
// NSData write to file with return type
// Reference: https://developer.apple.com/documentation/foundation/nsdata/write(tofile:atomically:)?language=objc
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
// Objective-C class method
// Reference: https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc
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
// LAContext biometry method (no params)
// Reference: https://developer.apple.com/documentation/localauthentication/lacontext/invalidate()?language=objc
// ============================================================================
const laContextHook: Frooky.ObjectiveCHook = {
  objcClass: 'LAContext',
  methods: [
    '- invalidate'
  ]
}

// ============================================================================
// Multiple methods in same class
// Reference: https://developer.apple.com/documentation/localauthentication/laprivatekey/decrypt(_:algorithm:completion:)?language=objc
// Reference: https://developer.apple.com/documentation/localauthentication/lapublickey/verify(_:signature:algorithm:completion:)?language=objc
// ============================================================================
const keychainHook: Frooky.ObjectiveCHook = {
  objcClass: 'LAPrivateKey',
  methods: [
    {
      name: '- decryptData:secKeyAlgorithm:completion:',
      params: [
        ['(NSData *)', 'data'],
        ['(SecKeyAlgorithm)', 'algorithm'],
        ['(void (^)(NSData *, NSError *))', 'handler']
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
// CoreData save with output parameter
// Reference: https://developer.apple.com/documentation/coredata/nsmanagedobjectcontext/save()?language=objc
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
  ]
}

// ============================================================================
// Network request with stack trace filtering
// Reference: https://developer.apple.com/documentation/foundation/urlsession/datatask(with:completionhandler:)-e6xv?language=objc
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
//  Method with both entry and exit decoding
// Reference: https://developer.apple.com/documentation/foundation/nsmutabledata/append(_:)?language=objc
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
