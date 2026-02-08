import * as Frooky from 'frooky'

// ============================================================================
// EXAMPLE 1: Single Java method (no arguments)
// ============================================================================
const wifiHook: Frooky.JavaHook = {
  javaClass: 'android.net.wifi.WifiManager',
  methods: [
    { name: 'getConnectionInfo' }
  ]
}

// ============================================================================
// EXAMPLE 2: Multiple Java methods
// ============================================================================
const locationHook: Frooky.JavaHook = {
  javaClass: 'android.location.LocationManager',
  methods: [
    { name: 'getLastKnownLocation' },
    { name: 'isProviderEnabled' },
    { name: 'requestLocationUpdates' }
  ],
  stackTraceLimit: 10
}

// ============================================================================
// EXAMPLE 3: Single overload
// ============================================================================
const urlHook: Frooky.JavaHook = {
  javaClass: 'java.net.URL',
  methods: [
    {
      name: 'openConnection',
      overloads: [
        {
          parameters: [
            { type: 'java.net.Proxy' }
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 4: Multiple overloads
// ============================================================================
const intentHook: Frooky.JavaHook = {
  javaClass: 'android.content.Intent',
  methods: [
    {
      name: 'putExtra',
      overloads: [
        {
          parameters: [
            { type: 'java.lang.String', name: 'name' },
            { type: 'java.lang.String', name: 'value' }
          ]
        },
        {
          parameters: [
            { type: 'java.lang.String', name: 'name' },
            { type: 'int', name: 'value' }
          ]
        },
        {
          parameters: [
            { type: 'java.lang.String', name: 'name' },
            { type: 'boolean', name: 'value' }
          ]
        },
        {
          parameters: [
            { type: 'java.lang.String', name: 'name' },
            { type: '[B', name: 'value' }
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 5: Custom decoder for Java method argument
// ============================================================================
const intentFlagsHook: Frooky.JavaHook = {
  javaClass: 'android.content.Intent',
  methods: [
    {
      name: 'setFlags',
      overloads: [
        {
          parameters: [
            {
              type: 'int',
              name: 'flags',
              decoder: 'IntentFlagsDecoder'
            }
          ]
        }
      ]
    }
  ],
  debug: true
}

// ============================================================================
// EXAMPLE 6: Single Java Type as argument
// ============================================================================
const activityHook: Frooky.JavaHook = {
  javaClass: 'android.app.Activity',
  methods: [
    {
      name: 'startActivity',
      overloads: [
        {
          parameters: [
            { type: 'android.content.Intent', name: 'intent' }
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 7: Multiple Java Types as arguments
// ============================================================================
const sqliteHook: Frooky.JavaHook = {
  javaClass: 'android.database.sqlite.SQLiteDatabase',
  methods: [
    {
      name: 'query',
      overloads: [
        {
          parameters: [
            { type: 'java.lang.String', name: 'table' },
            { type: '[Ljava.lang.String', name: 'columns' },
            { type: 'java.lang.String', name: 'selection' },
            { type: '[Ljava.lang.String', name: 'selectionArgs' },
            { type: 'java.lang.String', name: 'groupBy' },
            { type: 'java.lang.String', name: 'having' },
            { type: 'java.lang.String', name: 'orderBy' }
          ]
        }
      ]
    }
  ],
  stackTraceLimit: 15,
  stackTraceFilter: ['^java\\.', '^android\\.']
}

// ============================================================================
// EXAMPLE 8: Decode parameter at exit (data passed by reference)
// ============================================================================
const cipherHook: Frooky.JavaHook = {
  javaClass: 'javax.crypto.Cipher',
  methods: [
    {
      name: 'doFinal',
      overloads: [
        {
          parameters: [
            { 
              type: '[B', 
              name: 'output',
              decodeAt: 'exit'
            },
            { 
              type: 'int', 
              name: 'outputOffset' 
            }
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 9: Decode parameter at both entry and exit
// ============================================================================
const bufferHook: Frooky.JavaHook = {
  javaClass: 'java.nio.ByteBuffer',
  methods: [
    {
      name: 'put',
      overloads: [
        {
          parameters: [
            { 
              type: '[B', 
              name: 'src',
              decodeAt: 'both'
            }
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 10: Hook constructor
// ============================================================================
const webViewHook: Frooky.JavaHook = {
  javaClass: 'android.webkit.WebView',
  methods: [
    { name: '$init' },  // Constructor
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
