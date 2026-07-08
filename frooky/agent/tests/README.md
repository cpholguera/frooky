# Testing Framework Documentation

This is a small test framework which runs on the target. It should be used to unit test Frida code. frooky uses it to test its agent.

The following chapters explain how to write tests and how to use the framework to test remote Frida code.

## Running Tests

To run the tests, you need to:

1. **Compile the testing framework agent**

    For Android:  

    ```sh
    frida-compile tests/android/agent-runner.ts -o agent-test-android.js
    ```

    For iOS:

    ```sh
    frida-compile tests/ios/agent-runner.ts -o agent-test-ios.js
    ```

1. **Run the tests**

    Now use `run-tests.js` to run the agent on the desired target device:

    ```sh
    # Examples: Target is USB device mode:
    node run-tests.js -i org.owasp.mastestapp -u -p agent-test-android.js
    node run-tests.js -i 4926 -u -p agent-test-android.js
    node run-tests.js -i MASTestApp -u -p agent-test-android.js

    # Example: Target is local simulator:
    node run-tests.js -i org.owasp.mastestapp.MASTestApp-iOS -p agent-test-ios.js
    ```

## Writing Tests

Tests are written using `describe('testObject', () => {});`, `ìt('should do something', () => {})` and `expect(actualValue).to*(expectedValue)`.

The basic syntax is:

```typescript
describe('frooky', () => {
    it('should throw an exception of no hook file is provided.', () => {
        expect(1).toBe(1);
    })
});
```

Tests can be nested to any depth and can be synchronous or asynchronous.

The framework implicitly loads all files starting with `test_*.ts` located in the following folders:

- `./android/`
- `./ios/`
- `./shared/`

## Matchers

`expect(actualValue)` returns an Matcher which we can use to test for the expected value. Use the following functions to do that:

| Matcher               | Description                                 |
| --------------------- | ------------------------------------------- |
| `.toBe(value)`        | Strict equality (`===`)                     |
| `.toEqual(value)`     | Deep equality                               |
| `.toBeTruthy()`       | Value is truthy                             |
| `.toBeFalsy()`        | Value is falsy                              |
| `.toThrow()`          | Exception thrown                            |
| `.toThrow('message')` | Exception thrown  with matching sub-message |
| `.toThrow(error)`     | Exception thrown instance of class          |
| `.notToThrow(error)`  | Exception is not thrown                     |

### Async tests

Example with `Promise`:

```typescript
describe("classLoader", () => {
  it("should load the class asynchronously", () => {
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        resolve();
      }, 100);
    });
  });
});
```

The top level of the whole suite is run in sequence, this means, that if there are multiple asynchronous tests in one test suite, all of them need to be resolved before the next top level suite will be executed.

### Nested tests (suites)

A `describe()` can contain child `describe()` calls. A parent passes only if all children pass.

```typescript
describe('math', () => {
    it('should do addition right', () => {
        expect(1 + 1).toBe(2);
    });

    it('should do subtraction right', () => {
        expect(5 - 3).toBe(2);
    });
});
```

### Testing that something throws

```typescript
expect(() => {
    throw new Error('boom');
}).toThrow('boom');
```

## Result tree

Each `sendCallback` receives a hierarchical result object:

```javascript
{
    type: 'test-result',
    result: {
        name: 'math',
        passed: true,
        depth: 0,
        children: [
            { name: 'addition',    passed: true, depth: 1 },
            { name: 'subtraction', passed: true, depth: 1 }
        ]
    }
}
```

After all suites finish, a final `test-complete` message is sent:

```javascript
{ 
    type: 'test-complete', 
    success: true 
}
```
