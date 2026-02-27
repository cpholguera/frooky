import * as Frooky from 'frooky'

// ============================================================================
// Single Java method (no arguments)
// ============================================================================
const wifiHook: Frooky.JavaHook = {
  javaClass: 'android.net.wifi.WifiManager',
  methods: [
    'getConnectionInfo'
  ]
}

// ============================================================================
// Multiple Java methods
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

// ============================================================================
// Custom decoder for Java method argument
// ============================================================================
const intentFlagsHook: Frooky.JavaHook = {
  javaClass: 'android.content.Intent',
  methods: [
    {
      name: 'setFlags',
      overloads: [
        {
          params: [
            ['int', 'flags', { decoder: 'IntentFlagsDecoder' }]
          ]
        }
      ]
    }
  ],
  debug: true
}

// ============================================================================
// Single Java Type as argument
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
  stackTraceFilter: ['^java\\.', '^android\\.']
}

// ============================================================================
// Decode parameter at exit (data passed by reference)
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
