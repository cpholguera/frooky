import ObjC from "frida-objc-bridge";

test('iOS runtime smoke test', () => {
    expect(ObjC.available).toBeTruthy();

    const NSProcessInfo = ObjC.classes.NSProcessInfo;
    expect(!!NSProcessInfo).toBeTruthy();

    const processName = NSProcessInfo.processInfo().processName().toString();
    expect(processName.length > 0).toBeTruthy();

    expect(Process.id > 0).toBeTruthy();
});
