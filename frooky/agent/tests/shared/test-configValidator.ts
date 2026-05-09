import { validateMetadata } from "../../shared/configValidator";
import { FrookyMetadata } from "../../shared/frookyMetadata";

test("Test file validator.", () => {
  test("validateMetadata()", () => {
    test("successfully validates valid metadata.", () => {
      const validMetadata: FrookyMetadata = {
        platform: "Android",
        name: "Test Metadata",
        description: "Test Description",
        category: "Test",
        author: "frooky dev team",
        version: "1.0",
      };
      expect(() => {
        validateMetadata(validMetadata, "Android");
      }).notToThrow();
    });
  });
});
