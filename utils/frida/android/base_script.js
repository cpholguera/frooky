/**
 * Decodes the parameter types of a Java method.
 * @param {string} methodHeader - Java method (e.g., `function setBlockModes([Ljava.lang.String;): android.security.keystore.KeyGenParameterSpec$Builder`)
 * @returns {[string]} The decoded parameter types (e.g., "['[Ljava.lang.String;']")
 */
function parseParameterTypes(methodHeader) {
  var regex = /\((.*?)\)/;
  var parameterString = regex.exec(methodHeader)[1];
  if (parameterString === "") {
    return [];
  }
  return parameterString.replace(/ /g, "").split(",");
}

/**
 * Decodes the type of the return value of a Java method.
 * @param {string} methodHeader - Java method (e.g., "function setBlockModes([Ljava.lang.String;): android.security.keystore.KeyGenParameterSpec$Builder")
 * @returns {string} The decoded parameter types (e.g., "android.security.keystore.KeyGenParameterSpec$Builder")
 */
function parseReturnValue(methodHeader) {
  return methodHeader.split(":")[1].trim();
}

/**
 * Generates a v4 UUID
 * @returns {string} v4 UUID (e.g. "bf01006f-1d6c-4faa-8680-36818b4681bc")
 */
function generateUUID() {
  var d = new Date().getTime();
  var d2 =
    (typeof performance !== "undefined" &&
      performance.now &&
      performance.now() * 1000) ||
    0;
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
    var r = Math.random() * 16;
    if (d > 0) {
      r = (d + r) % 16 | 0;
      d = Math.floor(d / 16);
    } else {
      r = (d2 + r) % 16 | 0;
      d2 = Math.floor(d2 / 16);
    }
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}


/**
 * Overloads a method. If the method is called, the parameters and the return value are decoded and together with a stack trace send back to the frida.re client.
 * @param {string} clazz - Java class (e.g., "android.security.keystore.KeyGenParameterSpec$Builder").
 * @param {string} method - Name of the method which should be overloaded (e.g., "setBlockModes").
 * @param {number} overloadIndex - If there are overloaded methods available, this number represents them (e.g., 0 for the first one)
 * @param {string} categoryName - OWASP MAS category for easier identification (e.g., "CRYPTO")
 * @param {function} callback - Callback function. The function takes the information gathered as JSON string.
 * @param {number} maxFrames - Maximum number of stack frames to capture (default is 8,  set to -1 for unlimited frames).
 */
function registerHook(
  clazz,
  method,
  overloadIndex,
  categoryName,
  callback,
  maxFrames = 8
) {

  var Exception = Java.use("java.lang.Exception");
  const System = Java.use('java.lang.System');

  const toHook = Java.use(clazz)[method];

  const methodHeader = toHook.overloads[overloadIndex].toString();

  toHook.overloads[overloadIndex].implementation = function () {

    var st = Exception.$new().getStackTrace();
    var stackTrace = [];
    st.forEach(function (stElement, index) {
      if (maxFrames === -1 || index < maxFrames) {
        var stLine = stElement.toString();
        stackTrace.push(stLine);
      }
    });

    var parameterTypes = parseParameterTypes(methodHeader);
    var returnType = parseReturnValue(methodHeader);

    let instanceId;
    if (this && this.$className && typeof this.$h === 'undefined') {
      instanceId = 'static';
    } else {
      // call Java’s identityHashCode on the real object
      instanceId = System.identityHashCode(this);
    }

    const event = {
      id: generateUUID(),
      category: categoryName,
      time: new Date().toISOString(),
      class: clazz,
      method: method,
      instanceId: instanceId,
      stackTrace: stackTrace,
      inputParameters: decodeArguments(parameterTypes, arguments),
    };

    try {
      var returnValue = this[method].apply(this, arguments);
      event.returnValue = decodeArguments([returnType], [returnValue]);
      callback(event);
      return returnValue;
    } catch (e) {
      event.exception = e.toString();
      callback(event);
      throw e;
    }
  };
}

/**
 * Finds the overload index that matches the given argument types.
 * @param {Object} methodHandle - Frida method handle with overloads.
 * @param {[string]} argTypes - Array of argument type strings (e.g., ["android.net.Uri", "android.content.ContentValues"]).
 * @returns {number} The index of the matching overload, or -1 if not found.
 */
function findOverloadIndex(methodHandle, argTypes) {
  for (var i = 0; i < methodHandle.overloads.length; i++) {
    var overload = methodHandle.overloads[i];
    var parameterTypes = parseParameterTypes(overload.toString());
    
    if (parameterTypes.length !== argTypes.length) {
      continue;
    }
    
    var match = true;
    for (var j = 0; j < argTypes.length; j++) {
      if (parameterTypes[j] !== argTypes[j]) {
        match = false;
        break;
      }
    }
    
    if (match) {
      return i;
    }
  }
  return -1;
}

/**
 * Takes an array of objects usually defined in the `hooks.js` file of a DEMO and loads all classes and functions stated in there.
 * @param {[object]} hook - Contains a list of objects which contains all methods which will be overloaded.
 *   Basic format: {class: "android.security.keystore.KeyGenParameterSpec$Builder", methods: ["setBlockModes"]}
 *   With overloads: {class: "android.content.ContentResolver", method: "insert", overloads: [{args: ["android.net.Uri", "android.content.ContentValues"]}]}
 * @param {string} categoryName - OWASP MAS category for easier identification (e.g., "CRYPTO")
 * @param {function} callback - Callback function. The function takes the information gathered as JSON string.
 */
function registerAllHooks(hook, categoryName, callback) {
    // Check if specific overloads are defined with `method` (singular) and `overloads`
    if (hook.method && hook.overloads && hook.overloads.length > 0) {
      try {
        var toHook = Java.use(hook.class)[hook.method];
        
        for (var o = 0; o < hook.overloads.length; o++) {
          var overloadDef = hook.overloads[o];
          var argTypes = overloadDef.args || [];
          var overloadIndex = findOverloadIndex(toHook, argTypes);
          
          if (overloadIndex !== -1) {
            registerHook(hook.class, hook.method, overloadIndex, categoryName, callback, hook.maxFrames);
          } else {
            console.error(`Overload not found for ${hook.class}:${hook.method} with args [${argTypes.join(", ")}]`);
          }
        }
      } catch (err) {
        console.error(err);
        console.error(`Problem when overloading ${hook.class}:${hook.method}`);
      }
    }
    // Default behavior: hook all overloads for each method in `methods` array
    else if (hook.methods) {
      for (var m in hook.methods) {
        try {
          var toHook = Java.use(hook.class)[hook.methods[m]];

          var overloadCount = toHook.overloads.length;

          for (var i = 0; i < overloadCount; i++) {
            registerHook(hook.class, hook.methods[m], i, categoryName, callback, hook.maxFrames);
          }
        } catch (err) {
          console.error(err);
          console.error(`Problem when overloading ${hook.class}:${hook.methods[m]}`);
        }
      }
    }
}

Java.perform(function () {

  function callback(event){
    console.log(JSON.stringify(event, null, 2))
  }

  target.hooks.forEach(function (hook, _) {
    registerAllHooks(hook, target.category, callback);
  });

});
