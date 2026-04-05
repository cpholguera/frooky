# Testing Framework Documentation

This is a small test framework which runs on the target. It should be used to unit test Frida code. frooky uses it to test its agent.

The following chapters explain how to write tests and how to use the framework to test remote Frida code.

## Writing Tests

Tests are written using `test()` and `expect()`. Tests can be nested to any depth and can be synchronous or asynchronous.

## Matchers

| Matcher               | Description                                 |
| --------------------- | ------------------------------------------- |
| `.toBe(value)`        | Strict equality (`===`)                     |
| `.toEqual(value)`     | Deep equality                               |
| `.toBeTruthy()`       | Value is truthy                             |
| `.toBeFalsy()`        | Value is falsy                              |
| `.toThrow()`          | Exception thrown                            |
| `.toThrow('message')` | Exception thrown  with matching sub-message |
| `.toThrow(error)`     | Exception thrown instance of class          |

### Basic syntax

```typescript
test('my test', () => {
    expect(1).toBe(1);
});
```

### Async tests

Example with `Promise`:

```typescript
test('asyncTest', () => {
    return new Promise<void>(resolve => {
        setTimeout(() => { resolve(); }, 100);
    }
  )
);
```

The top level of the whole suite is run in sequence, this means, that if there are multiple asynchronous tests in one test suite, all of them need to be resolved before the next top level suite will be executed.

### Nested tests (suites)

A `test()` can contain child `test()` calls. A parent passes only if all children pass.

```typescript
test('math', () => {
    test('addition', () => {
        expect(1 + 1).toBe(2);
    });

    test('subtraction', () => {
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
