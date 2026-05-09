import { uuidv4 } from "../../shared/utils";

describe("uuidv4()", () => {
  it("should generate a valid UUID v4", () => {
    const uuid = uuidv4();
    const uuidV4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(uuidV4Regex.test(uuid)).toBeTruthy();
  });
});
