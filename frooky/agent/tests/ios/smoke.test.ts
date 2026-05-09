import ObjC from "frida-objc-bridge";

describe("iOS runtime", () => {
  it("should have ObjC available", () => {
    expect(ObjC.available).toBeTruthy();
  });

  it("should expose NSProcessInfo class", () => {
    expect(!!ObjC.classes.NSProcessInfo).toBeTruthy();
  });

  it("should have a valid process name", () => {
    const processName = ObjC.classes.NSProcessInfo.processInfo().processName().toString();
    expect(processName.length > 0).toBeTruthy();
  });

  it("should have a valid process ID", () => {
    expect(Process.id > 0).toBeTruthy();
  });
});

export {};
