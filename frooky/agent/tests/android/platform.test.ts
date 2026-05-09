import Java from "frida-java-bridge";

describe("Android runtime smoke test", () => {
  it("should have Java available", () =>
    new Promise<void>((resolve, reject) => {
      Java.perform(() => {
        try {
          expect(Java.available).toBeTruthy();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    }));

  it("should expose a valid OS release version string", () =>
    new Promise<void>((resolve, reject) => {
      Java.perform(() => {
        try {
          const BuildVersion = Java.use("android.os.Build$VERSION");
          const version = BuildVersion.RELEASE.value;
          expect(typeof version === "string" && version.length > 0).toBeTruthy();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    }));

  it("should have a valid process ID", () =>
    new Promise<void>((resolve, reject) => {
      Java.perform(() => {
        try {
          const AndroidProcess = Java.use("android.os.Process");
          const pid = AndroidProcess.myPid();
          expect(pid > 0).toBeTruthy();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    }));
});
