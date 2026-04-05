import Java from "frida-java-bridge";

test("Android runtime smoke test", () => {
  return new Promise<void>((resolve, reject) => {
    Java.perform(() => {
      try {
        expect(Java.available).toBeTruthy();

        const BuildVersion = Java.use("android.os.Build$VERSION");
        const version = BuildVersion.RELEASE.value;
        expect(typeof version === "string" && version.length > 0).toBeTruthy();

        const AndroidProcess = Java.use("android.os.Process");
        const pid = AndroidProcess.myPid();
        expect(pid > 0).toBeTruthy();

        resolve();
      } catch (error) {
        reject(error);
      }
    });
  });
});
