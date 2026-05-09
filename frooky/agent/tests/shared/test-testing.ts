describe("Tests for the testing framework. They may be moved to a dedicated test suite later.", () => {
  describe("toBe", () => {
    it("should pass when values are strictly equal", () => {
      expect(1).toBe(1);
      expect("hello").toBe("hello");
    });

    it("should fail when values are not strictly equal", () => {
      expect(() => {
        expect(1).toBe(2);
      }).toThrow();
      expect(() => {
        expect({ a: 1 }).toBe({ a: 1 });
      }).toThrow();
    });
  });

  describe("toEqual", () => {
    it("should pass when values are deeply equal", () => {
      expect({ a: 1 }).toEqual({ a: 1 });
      expect([1, 2, 3]).toEqual([1, 2, 3]);
    });

    it("should fail when values are not deeply equal", () => {
      expect(() => {
        expect({ a: 1 }).toEqual({ a: 2 });
      }).toThrow();
      expect(() => {
        expect([1, 2]).toEqual([1, 2, 3]);
      }).toThrow();
    });
  });

  describe("toBeTruthy", () => {
    it("should pass for truthy values", () => {
      expect(true).toBeTruthy();
      expect(1).toBeTruthy();
      expect("non-empty").toBeTruthy();
    });

    it("should fail for falsy values", () => {
      expect(() => {
        expect(false).toBeTruthy();
      }).toThrow();
      expect(() => {
        expect(0).toBeTruthy();
      }).toThrow();
      expect(() => {
        expect("").toBeTruthy();
      }).toThrow();
    });
  });

  describe("toBeFalsy", () => {
    it("should pass for falsy values", () => {
      expect(false).toBeFalsy();
      expect(0).toBeFalsy();
      expect(null).toBeFalsy();
      expect(undefined).toBeFalsy();
    });

    it("should fail for truthy values", () => {
      expect(() => {
        expect(true).toBeFalsy();
      }).toThrow();
      expect(() => {
        expect(1).toBeFalsy();
      }).toThrow();
      expect(() => {
        expect("hi").toBeFalsy();
      }).toThrow();
    });
  });

  describe("toThrow", () => {
    it("should pass when function throws with matching type", () => {
      expect(() => {
        throw new Error("boom");
      }).toThrow(new Error("boom"));
    });

    it("should pass when function throws with matching sub-message", () => {
      expect(() => {
        throw new Error("zapp boom zoink");
      }).toThrow("boom");
    });

    it("should reject a message mismatch", () => {
      expect(() => {
        expect(() => {
          throw new Error("cholula");
        }).toThrow("chipotle");
      }).toThrow();
    });

    it("should reject a type mismatch", () => {
      expect(() => {
        expect(() => {
          throw new Error("boom");
        }).toThrow(new TypeError("boom"));
      }).toThrow();
    });

    it("should reject a non-throwing function", () => {
      expect(() => {
        expect(() => {
          return 42;
        }).toThrow();
      }).toThrow();
    });
  });

  describe("asyncTest", () => {
    it("should resolve promise 1", () =>
      new Promise<void>((resolve) => {
        setTimeout(() => {
          resolve();
        }, 100);
      }));
    it("should resolve promise 2", () =>
      new Promise<void>((resolve) => {
        setTimeout(() => {
          resolve();
        }, 100);
      }));
  });

  describe("nestedTests", () => {
    it("should pass basic assertions at level 1", () => {
      expect(false).toBeFalsy();
      expect(true).toBeTruthy();
    });

    describe("level 2", () => {
      it("should pass basic assertions at level 2", () => {
        expect(false).toBeFalsy();
        expect(true).toBeTruthy();
      });

      describe("level 3", () => {
        it("should pass basic assertions at level 3 - 1", () => {
          expect(false).toBeFalsy();
          expect(true).toBeTruthy();
        });
        it("should pass basic assertions at level 3 - 2", () => {
          expect(false).toBeFalsy();
          expect(true).toBeTruthy();
        });
      });
    });
  });
});
