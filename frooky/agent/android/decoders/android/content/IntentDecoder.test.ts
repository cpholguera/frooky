import Java from "frida-java-bridge";
import { DEFAULT_DECODER_SETTINGS } from "../../../../shared/defaultValues";
import { IntentDecoder } from "./IntentDecoder";

describe("IntentDecoder", () => {
  const Intent = Java.use("android.content.Intent");
  const Uri = Java.use("android.net.Uri");
  const decoder = new IntentDecoder({
    type: "android.content.Intent",
    settings: DEFAULT_DECODER_SETTINGS,
  });

  it("should decode action", () => {
    const intent = Intent.$new("android.intent.action.VIEW");
    const result = decoder.decode(intent);
    expect(result.value.action).toBe("android.intent.action.VIEW");
  });

  it("should decode data URI", () => {
    const intent = Intent.$new("android.intent.action.VIEW", Uri.parse("https://mas.owasp.org"));
    const result = decoder.decode(intent);
    expect(result.value.data).toBe("https://mas.owasp.org");
  });

  it("should decode MIME type", () => {
    const intent = Intent.$new("android.intent.action.SEND");
    intent.setType("text/plain");
    const result = decoder.decode(intent);
    expect(result.value.type).toBe("text/plain");
  });

  it("should decode explicit component", () => {
    const intent = Intent.$new();
    intent.setClassName("org.owasp.mas", "org.owasp.mas.TargetActivity");
    const result = decoder.decode(intent);
    expect(result.value.component).toEqual({
      type: "android.content.ComponentName",
      value: {
        className: "org.owasp.mas.TargetActivity",
        packageName: "org.owasp.mas",
      },
    });
  });

  it("should decode package", () => {
    const intent = Intent.$new("android.intent.action.VIEW");
    intent.setPackage("org.owasp.mas");
    const result = decoder.decode(intent);
    expect(result.value.package).toBe("org.owasp.mas");
  });

  it("should decode flags", () => {
    const intent = Intent.$new("android.intent.action.VIEW");
    intent.setFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
    intent.addFlags(0x20000000); // FLAG_ACTIVITY_SINGLE_TOP
    const result = decoder.decode(intent);
    expect(result.value.flags).toEqual({
      type: "android.content.IntentFlag",
      value: ["FLAG_ACTIVITY_NEW_TASK", "FLAG_ACTIVITY_SINGLE_TOP"],
    });
  });

  it("should decode categories", () => {
    const intent = Intent.$new("android.intent.action.MAIN");
    intent.addCategory("android.intent.category.LAUNCHER");
    const result = decoder.decode(intent);
    expect(result.value.categories).toEqual({
      type: "java.util.Set<String>",
      value: [
        {
          type: "java.lang.String",
          value: {
            type: "java.lang.String",
            value: "android.intent.category.LAUNCHER",
          },
        },
      ],
    });
  });

  it("should decode extras", () => {
    const intent = Intent.$new("android.intent.action.SEND");
    intent.putExtra("android.intent.extra.TEXT", "hello world");
    const result = decoder.decode(intent);
    expect(result.value.extras).toEqual({
      type: "android.os.Bundle",
      value: [
        {
          type: "java.lang.String",
          name: "android.intent.extra.TEXT",
          value: "hello world",
        },
      ],
    });
  });

  it("should handle null fields on bare intent", () => {
    const intent = Intent.$new();
    const result = decoder.decode(intent);
    expect(result.value.action).toBeNull();
    expect(result.value.data).toBeNull();
    expect(result.value.type).toBeNull();
    expect(result.value.package).toBeNull();
    expect(result.value.component).toBeNull();
    expect(result.value.clipData).toBeNull();
    expect(result.value.categories).toBeNull();
    expect(result.value.extras).toBeNull();
  });
});

export {};
