import * as Frooky from 'frooky'

// ============================================================================
// EXAMPLE 1: Simple native function with basic types
// ============================================================================
const openHook: Frooky.NativeHook = {
  module: 'libc.so',
  functions: [
    {
      symbol: 'open',
      returnType: 'int',
      params: [
        { type: 'const char *', name: 'pathname' },
        { type: 'int', name: 'flags' },
        { type: 'mode_t', name: 'mode' }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 2: Function with pointer and buffer
// ============================================================================
const readHook: Frooky.NativeHook = {
  module: 'libc.so',
  functions: [
    {
      symbol: 'read',
      returnType: 'ssize_t',
      params: [
        { type: 'int', name: 'fd' },
        { type: 'void *', name: 'buf', decodeAt: 'exit' },
        { type: 'size_t', name: 'count' }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 3: OpenSSL encryption function
// ============================================================================
const encryptHook: Frooky.NativeHook = {
  module: 'libcrypto.so',
  functions: [
    {
      symbol: 'EVP_EncryptInit_ex',
      returnType: 'int',
      params: [
        { type: 'EVP_CIPHER_CTX *', name: 'ctx' },
        { type: 'const EVP_CIPHER *', name: 'type' },
        { type: 'ENGINE *', name: 'impl' },
        { type: 'const unsigned char *', name: 'key' },
        { type: 'const unsigned char *', name: 'iv' }
      ]
    }
  ],
  stackTraceLimit: 10
}

// ============================================================================
// EXAMPLE 4: SSL write with buffer
// ============================================================================
const sslWriteHook: Frooky.NativeHook = {
  module: 'libssl.so',
  functions: [
    {
      symbol: 'SSL_write',
      returnType: 'int',
      params: [
        { type: 'SSL *', name: 'ssl' },
        { type: 'const void *', name: 'buf' },
        { type: 'int', name: 'num' }
      ]
    }
  ],
  debug: true
}

// ============================================================================
// EXAMPLE 5: Multiple functions in same module
// ============================================================================
const opensslHook: Frooky.NativeHook = {
  module: 'libssl.so',
  functions: [
    {
      symbol: 'ENGINE_load_builtin_engines'
    },
    {
      symbol: 'ENGINE_cleanup'
    },
    {
      symbol: 'OSSL_CMP_validate_cert_path',
      returnType: 'int',
      params: [
        { type: 'const OSSL_CMP_CTX *', name: 'ctx' },
        { type: 'X509_STORE *', name: 'trusted_store' },
        { type: 'X509 *', name: 'cert' }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 6: Function with custom decoder
// ============================================================================
const customDecoderHook: Frooky.NativeHook = {
  module: 'libcustom.so',
  functions: [
    {
      symbol: 'process_data',
      returnType: 'int',
      params: [
        { 
          type: 'void *', 
          name: 'data',
          decoder: 'CustomDataDecoder'
        },
        { type: 'size_t', name: 'size' }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 7: Function with output parameter decoded at exit
// ============================================================================
const outputParamHook: Frooky.NativeHook = {
  module: 'libexample.so',
  functions: [
    {
      symbol: 'get_buffer',
      returnType: 'int',
      params: [
        { 
          type: 'unsigned char *', 
          name: 'output',
          decodeAt: 'exit'  // Decode after function fills the buffer
        },
        { type: 'size_t', name: 'size' }
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
