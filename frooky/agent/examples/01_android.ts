import * as Frooky from '../types/index'

// ============================================================================
// Single Java method (no arguments)
// Reference: https://developer.android.com/reference/android/net/wifi/WifiManager#getConnectionInfo()
// ============================================================================
const wifiHook: Frooky.JavaHook = {
  javaClass: 'android.net.wifi.WifiManager',
  methods: [
    'getConnectionInfo'
  ]
}

// ============================================================================
// Multiple Java methods
// Reference: https://developer.android.com/reference/android/location/LocationManager
// ============================================================================
const locationHook: Frooky.JavaHook = {
  javaClass: 'android.location.LocationManager',
  methods: [
    'getLastKnownLocation',
    'isProviderEnabled',
    'requestLocationUpdates'
  ],
  stackTraceLimit: 10
}

// ============================================================================
// Single overload
// Reference: https://developer.android.com/reference/java/net/URL#openConnection(java.net.Proxy)
// ============================================================================
const urlHook: Frooky.JavaHook = {
  javaClass: 'java.net.URL',
  methods: [
    {
      name: 'openConnection',
      overloads: [
        {
          params: ['java.net.Proxy']
        }
      ]
    }
  ]
}

// ============================================================================
// Multiple overloads
// Reference: https://developer.android.com/reference/android/content/Intent
// ============================================================================
const intentHook: Frooky.JavaHook = {
  javaClass: 'android.content.Intent',
  methods: [
    {
      name: 'putExtra',
      overloads: [
        {
          params: [
            ['java.lang.String', 'name'],
            ['java.lang.String', 'value']
          ]
        },
        {
          params: [
            ['java.lang.String', 'name'],
            ['int', 'value']
          ]
        },
        {
          params: [
            ['java.lang.String', 'name'],
            ['boolean', 'value']
          ]
        },
        {
          params: [
            ['java.lang.String', 'name'],
            ['[B', 'value']
          ]
        }
      ]
    }
  ]
}

// // ============================================================================
// // Custom decoder for Java method argument
// // Reference: https://developer.android.com/reference/android/content/Intent#setFlags(int)
// // ============================================================================
// const intentFlagsHook: Frooky.JavaHook = {
//   javaClass: 'android.content.Intent',
//   methods: [
//     {
//       name: 'setFlags',
//       overloads: [
//         {
//           params: [
//             ['int', 'flags', { decoder: 'IntentFlagsDecoder' }]
//           ]
//         }
//       ]
//     }
//   ]
// }

// ============================================================================
// Single Java Type as argument
// Reference: https://developer.android.com/reference/android/app/Activity#startActivity(android.content.Intent)
// ============================================================================
const activityHook: Frooky.JavaHook = {
  javaClass: 'android.app.Activity',
  methods: [
    {
      name: 'startActivity',
      overloads: [
        {
          params: [
            ['android.content.Intent', 'intent']
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// Multiple Java Types as arguments
// Reference: https://developer.android.com/reference/android/database/sqlite/SQLiteDatabase#query(java.lang.String,%20java.lang.String[],%20java.lang.String,%20java.lang.String[],%20java.lang.String,%20java.lang.String,%20java.lang.String) <kcite ref="1"/>
// ============================================================================
const sqliteHook: Frooky.JavaHook = {
  javaClass: 'android.database.sqlite.SQLiteDatabase',
  methods: [
    {
      name: 'query',
      overloads: [
        {
          params: [
            ['java.lang.String', 'table'],
            ['[Ljava.lang.String', 'columns'],
            ['java.lang.String', 'selection'],
            ['[Ljava.lang.String', 'selectionArgs'],
            ['java.lang.String', 'groupBy'],
            ['java.lang.String', 'having'],
            ['java.lang.String', 'orderBy']
          ]
        }
      ]
    }
  ],
  stackTraceLimit: 15,
  stackTraceFilter: ['^java\.', '^android\.']
}

// ============================================================================
// Decode parameter at exit (data passed by reference)
// Reference: https://developer.android.com/reference/javax/crypto/Cipher#doFinal(byte[],%20int)
// ============================================================================
const cipherHook: Frooky.JavaHook = {
  javaClass: 'javax.crypto.Cipher',
  methods: [
    {
      name: 'doFinal',
      overloads: [
        {
          params: [
            ['[B', 'output', { decodeAt: 'exit' }],
            ['int', 'outputOffset']
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// Decode parameter at both entry and exit
// Reference: https://developer.android.com/reference/java/nio/ByteBuffer#put(byte[])
// ============================================================================
const bufferHook: Frooky.JavaHook = {
  javaClass: 'java.nio.ByteBuffer',
  methods: [
    {
      name: 'put',
      overloads: [
        {
          params: [
            ['[B', 'src', { decodeAt: 'both' }]
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// Hook constructor
// Reference: https://developer.android.com/reference/android/webkit/WebView#WebView(android.content.Context)
// ============================================================================
const webViewHook: Frooky.JavaHook = {
  javaClass: 'android.webkit.WebView',
  methods: [
    { name: '$init' },
    { name: 'loadUrl' }
  ]
}

export {
  wifiHook,
  locationHook,
  urlHook,
  intentHook,
  intentFlagsHook,
  activityHook,
  sqliteHook,
  cipherHook,
  bufferHook,
  webViewHook
}
