import { afterAll, beforeAll, describe, expect, it, setSystemTime } from "bun:test";
import { calculateEpochExpiry, formatUrl, sanitizeUri } from "../../src/utils/format";

describe("formatUrl", () => {
  const expected = "https://test.com/";

  it("should prepend 'https://' if missing", () => {
    const url = "test.com";
    expect(formatUrl(url)).toBe(expected);
  });

  it("should allow http:// for localhost url", () => {
    const localhost = "http://localhost:3000/";
    expect(formatUrl(localhost)).toBe(localhost);
  });

  it("should set protocol to HTTPS", () => {
    expect(formatUrl("http://test.com")).toBe("https://test.com/");
    expect(formatUrl("ftp://test.com")).toBe("https://test.com/");
  });
});

describe("calculateEpochExpiry", () => {
  const expiresIn = 30000;
  const now = 1737751858;
  const expected = now + expiresIn;

  beforeAll(() => {
    setSystemTime(1737751858716);
  });

  afterAll(() => {
    setSystemTime();
  });

  it("should add the expiry to the auth time", () => {
    expect(calculateEpochExpiry(String(expiresIn), String(now))).toBe(expected);
  });

  it("should default to the current time", () => {
    expect(calculateEpochExpiry(String(expiresIn))).toBe(expected);
  });
});

describe("sanitizeUri", () => {
  it("removes trailing '?'", () => {
    const url = "https://test.com/?foo=bar";
    expect(sanitizeUri(url)).toBe("https://test.com/");
  });
});
