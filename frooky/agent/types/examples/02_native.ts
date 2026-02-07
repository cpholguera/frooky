import * as Frooky from 'frooky'

// ============================================================================
// EXAMPLE 1: Simple native function with basic types
// ============================================================================
const openHook: Frooky.NativeHook = {
  module: 'libc.so',
  symbol: 'open',
  args: [
    { name: 'pathname', type: 'string' },
    { name: 'flags', type: 'int32' },
    { name: 'mode', type: 'int32' },
    { name: 'fd', type: 'int32', retValue: true }
  ]
}

// ============================================================================
// EXAMPLE 2: Function with pointer and length
// ============================================================================
const readHook: Frooky.NativeHook = {
  module: 'libc.so',
  symbol: 'read',
  args: [
    { name: 'fd', type: 'int32' },
    { name: 'buf', type: 'bytes', lengthInArg: 2, direction: 'out' },
    { name: 'count', type: 'uint32' },
    { name: 'bytesRead', type: 'int32', retValue: true }
  ]
}

// ============================================================================
// EXAMPLE 3: OpenSSL encryption function
// ============================================================================
const encryptHook: Frooky.NativeHook = {
  module: 'libcrypto.so',
  symbol: 'EVP_EncryptInit_ex',
  args: [
    { name: 'ctx', type: 'pointer' },
    { name: 'type', type: 'pointer' },
    { name: 'impl', type: 'pointer' },
    { name: 'key', type: 'bytes', length: 32 },
    { name: 'iv', type: 'bytes', length: 16 },
    { name: 'result', type: 'int32', retValue: true }
  ],
  stackTraceLimit: 10
}

// ============================================================================
// EXAMPLE 4: SSL write with dynamic buffer
// ============================================================================
const sslWriteHook: Frooky.NativeHook = {
  module: 'libssl.so',
  symbol: 'SSL_write',
  args: [
    { name: 'ssl', type: 'pointer' },
    { name: 'buf', type: 'bytes', lengthInArg: 2 },
    { name: 'num', type: 'int32' },
    { name: 'written', type: 'int32', retValue: true }
  ],
  debug: true
}


export { openHook, readHook, encryptHook, sslWriteHook }