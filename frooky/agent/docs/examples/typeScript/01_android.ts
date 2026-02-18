import * as Frooky from 'frooky'

// ============================================================================
// EXAMPLE 1: Single Java method (no arguments)
// ============================================================================
const wifiHook: Frooky.JavaHook = {
  javaClass: 'android.net.wifi.WifiManager',
  methods: [
    'getConnectionInfo'
  ]
}

// ============================================================================
// EXAMPLE 2: Multiple Java methods
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
// EXAMPLE 3: Single overload
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
// EXAMPLE 4: Multiple overloads
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
// EXAMPLE 5: Custom decoder for Java method argument
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
// EXAMPLE 6: Single Java Type as argument
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
// EXAMPLE 7: Multiple Java Types as arguments
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
// EXAMPLE 8: Decode parameter at exit (data passed by reference)
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
// EXAMPLE 9: Decode parameter at both entry and exit
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
// EXAMPLE 10: Hook constructor
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
