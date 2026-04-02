import * as Frooky from '../types/index'

// ============================================================================
// Simple native function with basic types, no param / return value decoding
// ============================================================================
const openHookSimple: Frooky.NativeHook = {
  module: 'libc.so',
  functions: [
    "open"
  ]
}

// ============================================================================
//  Native function with basic types
// ============================================================================
const openHook: Frooky.NativeHook = {
  module: 'libc.so',
  functions: [
    {
      symbol: 'open',
      returnType: 'int',
      params: [
        ['const char *', 'pathname'],
        ['int', 'flags'],
        ['mode_t', 'mode']
      ]
    }
  ]
}

// ============================================================================
// Function with pointer and buffer
// ============================================================================
const readHook: Frooky.NativeHook = {
  module: 'libc.so',
  functions: [
    {
      symbol: 'read',
      returnType: 'ssize_t',
      params: [
        ['int', 'fd'],
        ['void *', 'buf', { decodeAt: 'exit' }],
        ['size_t', 'count']
      ]
    }
  ]
}

// ============================================================================
// OpenSSL encryption function
// ============================================================================
const encryptHook: Frooky.NativeHook = {
  module: 'libcrypto.so',
  functions: [
    {
      symbol: 'EVP_EncryptInit_ex',
      returnType: 'int',
      params: [
        ['EVP_CIPHER_CTX *', 'ctx'],
        ['const EVP_CIPHER *', 'type'],
        ['ENGINE *', 'impl'],
        ['const unsigned char *', 'key'],
        ['const unsigned char *', 'iv']
      ]
    }
  ],
  stackTraceLimit: 10
}

// ============================================================================
// SSL write with buffer
// ============================================================================
const sslWriteHook: Frooky.NativeHook = {
  module: 'libssl.so',
  functions: [
    {
      symbol: 'SSL_write',
      returnType: 'int',
      params: [
        ['SSL *', 'ssl'],
        ['const void *', 'buf'],
        ['int', 'num']
      ]
    }
  ],
  debug: true
}

// ============================================================================
// Multiple functions in same module
// ============================================================================
const opensslHook: Frooky.NativeHook = {
  module: 'libssl.so',
  functions: [
    { symbol: 'ENGINE_load_builtin_engines' },
    { symbol: 'ENGINE_cleanup' },
    {
      symbol: 'OSSL_CMP_validate_cert_path',
      returnType: 'int',
      params: [
        ['const OSSL_CMP_CTX *', 'ctx'],
        ['X509_STORE *', 'trusted_store'],
        ['X509 *', 'cert']
      ]
    }
  ]
}

// ============================================================================
// Function with custom decoder
// ============================================================================
const customDecoderHook: Frooky.NativeHook = {
  module: 'libcustom.so',
  functions: [
    {
      symbol: 'process_data',
      returnType: 'int',
      params: [
        ['void *', 'data', { decoder: 'CustomDataDecoder' }],
        ['size_t', 'size']
      ]
    }
  ]
}

// ============================================================================
// Function with output parameter decoded at exit
// ============================================================================
const outputParamHook: Frooky.NativeHook = {
  module: 'libexample.so',
  functions: [
    {
      symbol: 'get_buffer',
      returnType: 'int',
      params: [
        ['unsigned char *', 'output', { decodeAt: 'exit' }],
        ['size_t', 'size']
      ]
    }
  ]
}

export {
  openHook,
  readHook,
  encryptHook,
  sslWriteHook,
  opensslHook,
  customDecoderHook,
  outputParamHook
}
