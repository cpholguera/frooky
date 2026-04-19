import Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../../../shared/decoders/decoder";
import type { Param } from "../../../../shared/hook/parameter";
import { JavaDecoder } from "../../javaDecoder";

export const SetDecoder: Decoder = {
  decode: (input: unknown, param: Param): DecodedValue => {
    const values: DecodedValue[] = [];

    if (input !== null && input !== undefined) {
      const set = Java.cast(input as any, Java.use("java.util.Set"));
      const iterator = set.iterator();

      while (iterator.hasNext()) {
        let element = iterator.next();

        const elementType = element === null || element === undefined ? "java.lang.Object" : (element.$className ?? element.getClass().getName());

        // Re-cast so the wrapper exposes the real class's methods/value
        if (element !== null && element !== undefined && elementType !== "java.lang.Object") {
          element = Java.cast(element, Java.use(elementType));
        }

        values.push(JavaDecoder.decode(element, { type: elementType } as Param));
      }
    }

    return {
      type: param.type,
      name: param.name,
      value: values,
    };
  },
};
