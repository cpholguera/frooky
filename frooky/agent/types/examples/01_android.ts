/**
 * This file contains examples of frooky hooks based in the defined API spec
 * and their declaration in YAML. 
 * 
 * The point is to test them here how they
 * look and work in practice. 
 * 
 * This the examples could then be moved to 
 * the documentation or examples/ folder
 */



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
          args: [
            { name: 'java.net.Proxy' }
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
          args: [
            { name: 'java.lang.String' },
            { name: 'java.lang.String' }
          ]
        },
        {
          args: [
            { name: 'java.lang.String' },
            { name: 'int' }
          ]
        },
        {
          args: [
            { name: 'java.lang.String' },
            { name: 'boolean' }
          ]
        },
        {
          args: [
            { name: 'java.lang.String' },
            { name: '[B' }  // byte array
          ]
        }
      ]
    }
  ]
}

// ============================================================================
// EXAMPLE 5: Custom decoder for Java method
// ============================================================================
const intentFlagsHook: Frooky.JavaHook = {
  javaClass: 'android.content.Intent',
  methods: [
    {
      name: 'setFlags',
      overloads: [
        {
          args: [
            { 
              name: 'int',
              decoder: 'IntentFlagsDecoder'
            }
          ]
        }
      ],
      decoder: 'IntentFlagsDecoder'
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
          args: [
            { name: 'android.content.Intent' }
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
          args: [
            { name: 'java.lang.String' },      // table
            { name: '[Ljava.lang.String;' },   // columns
            { name: 'java.lang.String' },      // selection
            { name: '[Ljava.lang.String;' },   // selectionArgs
            { name: 'java.lang.String' },      // groupBy
            { name: 'java.lang.String' },      // having
            { name: 'java.lang.String' }       // orderBy
          ]
        }
      ]
    }
  ],
  stackTraceLimit: 15,
  stackTraceFilter: ['^java\\.', '^android\\.']
}


export { 
  wifiHook, 
  locationHook,
  urlHook,
  intentHook,
  intentFlagsHook,
  activityHook,
  sqliteHook
}