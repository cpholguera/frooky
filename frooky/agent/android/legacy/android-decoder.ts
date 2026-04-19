import Java from "frida-java-bridge";
import { toHex } from "../../shared/utils.js";

/**
 * Generates a simple hash from a string.
 * @param {string} str - String to hash.
 * @returns {number} Hash value as a 32-bit integer.
 */
function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h << 5) - h + str.charCodeAt(i);
    h = h | 0;
  }
  return h;
}

/**
 * Decodes an RSA key (public or private) and extracts key parameters.
 * @param {Object} value - Reference to the Java key object.
 * @returns {Object} Object containing key parameters (modulusHex, modulusBitLength, publicExponentDec, privateExponentDec, keyHash).
 */
function decodeRSAKey(value) {
  const out = {};

  try {
    // Load RSA interfaces
    const RSAKey = Java.use("java.security.interfaces.RSAKey");
    const RSAPub = Java.use("java.security.interfaces.RSAPublicKey");
    const RSAPriv = Java.use("java.security.interfaces.RSAPrivateKey");
    let RSAPrivateCrt = null;
    try {
      RSAPrivateCrt = Java.use("java.security.interfaces.RSAPrivateCrtKey");
    } catch (_) {
      RSAPrivateCrt = null;
    }

    // Any RSA key, public or private, for modulus
    try {
      const anyRsa = Java.cast(value, RSAKey);
      const modBI = anyRsa.getModulus();
      out.modulusHex = modBI.toString(16);
      out.modulusBitLength = modBI.bitLength();
    } catch (_) {
      // not an RSAKey or keystore backend hides it, ignore
    }

    // Public key exponent
    try {
      const vpub = Java.cast(value, RSAPub);
      const expBI = vpub.getPublicExponent();
      if (expBI) {
        out.publicExponentDec = expBI.toString(10);
      }
    } catch (_) {
      // not an RSAPublicKey
    }

    // Private key exponents, may be unavailable for keystore backed keys
    if (RSAPrivateCrt !== null) {
      try {
        const vprivCrt = Java.cast(value, RSAPrivateCrt);
        const dBI = vprivCrt.getPrivateExponent();
        const eBI = vprivCrt.getPublicExponent();
        if (dBI) {
          out.privateExponentDec = dBI.toString(10);
        }
        if (eBI) {
          out.publicExponentDec = eBI.toString(10);
        }
      } catch (_) {
        // not an RSAPrivateCrtKey
      }
    } else {
      try {
        const vpriv = Java.cast(value, RSAPriv);
        const dBI2 = vpriv.getPrivateExponent();
        if (dBI2) {
          out.privateExponentDec = dBI2.toString(10);
        }
      } catch (_) {
        // not an RSAPrivateKey
      }
    }
  } catch (_) {
    // key interface logic failed, out remains minimal
  }

  if (out.modulusHex != null) {
    out.keyHash = simpleHash(out.modulusHex);
  }

  return out;
}

/**
 * Decodes a Java object according to its type.
 * @param {string} type - Java type of the value (e.g., "java.util.Set", "java.lang.String" or "int")
 * @param {Object} value - Reference to the object.
 * @returns {string} The type-appropriate decoded string (e.g., "[1,50,21]", "Hello World" or "-12")
 */
function decodeValue(type, value) {
  let readableValue = "";

  try {
    if (value == null) {
      readableValue = "void";
    } else {
      switch (type) {
        case "java.util.Set":
          readableValue = value.toArray().toString();
          break;

        case "java.util.Map": {
          const entrySet = value.entrySet();
          readableValue = entrySet.toArray().toString();
          break;
        }

        case "[B":
          // for performance reasons only decode the first 256 bytes of the full byte array
          readableValue = toHex(value, 256);
          break;

        case "[C":
          readableValue = "";
          for (const i in value) {
            readableValue = readableValue + value[i];
          }
          break;

        case "java.io.File":
          readableValue = value.getAbsolutePath();
          break;

        case "java.util.Date": {
          const DateFormat = Java.use("java.text.DateFormat");
          const formatter = DateFormat.getDateTimeInstance(DateFormat.MEDIUM.value, DateFormat.SHORT.value);
          readableValue = formatter.format(value);
          break;
        }

        case "androidx.sqlite.db.SupportSQLiteQuery":
          readableValue = value.getSql();
          break;

        case "android.content.ClipData$Item":
          readableValue = value.getText().toString();
          break;

        case "androidx.datastore.preferences.core.Preferences$Key":
        case "java.lang.Object":
        case "android.net.Uri":
        case "java.lang.CharSequence":
          readableValue = value.toString();
          break;

        /*
        1. No `RSAKey.class.isAssignableFrom` or `Java.isInstanceOf` for the RSA interfaces, instead each RSA interface is tried with `Java.cast` inside a `try` block. If the object does not implement that interface, the cast throws and is ignored. If it does, the cast succeeds and you can call the RSA methods.
        2. Modulus is obtained through `RSAKey.getModulus()`, which should cover both `OpenSSLRSAPublicKey` and `AndroidKeyStoreRSAPrivateKey` as long as the backend exposes the modulus.
        3. Exponents come from `RSAPublicKey.getPublicExponent()` and `RSAPrivateKey` or `RSAPrivateCrtKey` for the private exponent, but note that keystore backed private keys may refuse to expose the private exponent, so missing private exponent is expected in that case, while the public key parameters should still be visible.
        */

        case "java.security.PrivateKey":
        case "java.security.PublicKey":
        case "java.security.Key":
          try {
            readableValue = decodeRSAKey(value);
          } catch (e) {
            readableValue = value;
          }
          break;

        case "[Ljava.lang.Object;": {
          let out = "";
          for (const i in value) {
            out = out + value[i] + ", ";
          }
          readableValue = out;
          break;
        }

        case "java.util.Enumeration": {
          const elements = [];
          while (value.hasMoreElements()) {
            elements.push(value.nextElement().toString());
          }
          readableValue = JSON.stringify(elements);
          break;
        }

        case "android.database.Cursor":
          readableValue = decodeCursor(value);
          break;

        default:
          readableValue = value;
          break;
      }
    }
  } catch (e) {
    console.error("Value decoding exception: " + e);
    readableValue = value;
  }

  return readableValue;
}

/**
 * Decodes a `android.database.Cursor` object.
 * @param {object} value - Reference to the object.
 * @returns {string} The decoded rows and columns.
 */
function decodeCursor(value) {
  let out = "";
  const cursor = value;
  const originalCursorPosition = cursor.getPosition();

  // rows
  for (let i = 0; i < cursor.getColumnCount(); i++) {
    const columnName = cursor.getColumnName(i);
    out = out + columnName + " | ";
  }

  out = out + "\n----------------------\n";

  // columns
  if (cursor.moveToFirst()) {
    do {
      for (let i = 0; i < cursor.getColumnCount(); i++) {
        try {
          const columnValue = cursor.getString(i);
          out = out + columnValue + " | ";
        } catch (e) {
          out = out + " | ";
        }
      }
      out = out + "\n";
    } while (cursor.moveToNext());

    cursor.moveToPosition(originalCursorPosition);
  }
  return out;
}
