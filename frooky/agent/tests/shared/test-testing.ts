test('Tests for the testing framework. They may be moved to a dedicated test suite later.', () => {
  test('toBe', () => {
    test("passes when values are strictly equal", () => {
      expect(1).toBe(1);
      expect("hello").toBe("hello");
    });

    test("fails when values are not strictly equal", () => {
      expect(() => { expect(1).toBe(2); }).toThrow();
      expect(() => { expect({ a: 1 }).toBe({ a: 1 }); }).toThrow();
    });
  });

  test('toEqual', () => {
    test("passes when values are deeply equal", () => {
      expect({ a: 1 }).toEqual({ a: 1 });
      expect([1, 2, 3]).toEqual([1, 2, 3]);
    });

    test("fails when values are not deeply equal", () => {
      expect(() => { expect({ a: 1 }).toEqual({ a: 2 }); }).toThrow();
      expect(() => { expect([1, 2]).toEqual([1, 2, 3]); }).toThrow();
    });
  });

  test('toBeTruthy', () => {
    test("passes for truthy values", () => {
      expect(true).toBeTruthy();
      expect(1).toBeTruthy();
      expect("non-empty").toBeTruthy();
    });

    test("fails for falsy values", () => {
      expect(() => { expect(false).toBeTruthy(); }).toThrow();
      expect(() => { expect(0).toBeTruthy(); }).toThrow();
      expect(() => { expect("").toBeTruthy(); }).toThrow();
    });
  });

  test('toBeFalsy', () => {
    test("passes for falsy values", () => {
      expect(false).toBeFalsy();
      expect(0).toBeFalsy();
      expect(null).toBeFalsy();
      expect(undefined).toBeFalsy();
    });

    test("fails for truthy values", () => {
      expect(() => { expect(true).toBeFalsy(); }).toThrow();
      expect(() => { expect(1).toBeFalsy(); }).toThrow();
      expect(() => { expect("hi").toBeFalsy(); }).toThrow();
    });
  });

  test('toThrow', () => {
    test("passes when function throws with matching type", () => {
      expect(() => { throw new Error("boom"); }).toThrow(new Error("boom"));
    });

    test("passes when function throws with matching sub-message", () => {
      expect(() => { throw new Error("zapp boom zoink"); }).toThrow("boom");
    });

    test("correctly rejects message mismatch", () => {
      expect(() => {
        expect(() => { throw new Error("cholula"); }).toThrow("chipotle");
      }).toThrow();
    });

    test("correctly rejects type mismatch", () => {
      expect(() => {
        expect(() => { throw new Error("boom"); }).toThrow(new TypeError("boom"));
      }).toThrow();
    });

    test("correctly rejects non-throwing function", () => {
      expect(() => {
        expect(() => { return 42; }).toThrow();
      }).toThrow();
    });
  });

  test('asyncTest', () => {
    test('asyncResolve1', () => new Promise<void>(resolve => {
      setTimeout(() => { resolve(); }, 100);
    }));
    test('asyncResolve2', () => new Promise<void>(resolve => {
      setTimeout(() => { resolve(); }, 100);
    }));
  });

  test('nestedTests', () => {
    test("level 1", () => {
      expect(false).toBeFalsy();
      expect(true).toBeTruthy();
      test("level 2", () => {
        expect(false).toBeFalsy();
        expect(true).toBeTruthy();
        test("level 3 - 1", () => {
          expect(false).toBeFalsy();
          expect(true).toBeTruthy();
        });
        test("level 3 - 2", () => {
          expect(false).toBeFalsy();
          expect(true).toBeTruthy();
        });
      });
    });
  });
});
