import * as Frooky from '../types/frookyConfig'

// ============================================================================
// Simple native function with basic types, no param / return value decoding
// Reference: https://www.man7.org/linux/man-pages/man2/open.2.html
// ============================================================================
const openHookSimple: Frooky.NativeHook = {
  module: 'libc.so',
  functions: [
    "open"
  ]
}

// ============================================================================
// Native function with basic types
// Reference: https://www.man7.org/linux/man-pages/man2/open.2.html
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
// Reference: https://man7.org/linux/man-pages/man2/read.2.html
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
// Reference: https://docs.openssl.org/3.0/man3/EVP_EncryptInit/
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
// Reference: https://docs.openssl.org/4.0/man3/SSL_write/
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
  ]
}

// ============================================================================
// Multiple functions in same module
// Reference: https://docs.openssl.org/4.0/man3/OSSL_CMP_validate_msg/
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
