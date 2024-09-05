import { afterAll, afterEach, describe, expect, jest, spyOn, test } from "bun:test";
// biome-ignore lint: needed for spyOn
import * as browser from "../../src/utils/browser";
import {
  NO_DEFAULT_IDAAS_CLIENT,
  TEST_BASE_URI,
  TEST_ONBOARDING_RESPONSE,
  TEST_REDIRECT_URI,
  TEST_USER_ID,
} from "../constants";
import { mockFetch } from "../helpers";

// @ts-ignore private method
const spyOnGenerateSignUpUrl = spyOn(NO_DEFAULT_IDAAS_CLIENT, "generateSignUpUrl");
// @ts-ignore not full type
const _spyOnFetch = spyOn(window, "fetch").mockImplementation(mockFetch);

afterAll(() => {
  jest.restoreAllMocks();
});

afterEach(() => {
  localStorage.clear();
  jest.clearAllMocks();
});
describe("IdaasClient.signUp", () => {
  test("calls generateSignUpUrl", async () => {
    await NO_DEFAULT_IDAAS_CLIENT.signUp();
    expect(spyOnGenerateSignUpUrl).toBeCalled();
  });

  describe("generateSignUpUrl", () => {
    test("appends `response_mode=web_message` if `popup` is true", async () => {
      // @ts-ignore private method
      await NO_DEFAULT_IDAAS_CLIENT.generateSignUpUrl({ popup: true });
      const value = (await spyOnGenerateSignUpUrl.mock.results[0].value) as string;

      expect(value.split("&")).toContain("response_mode=web_message");
    });

    test("does not append a `response_mode` if `popup` is false", async () => {
      await NO_DEFAULT_IDAAS_CLIENT.signUp({ redirectUri: TEST_REDIRECT_URI });
      const value = (await spyOnGenerateSignUpUrl.mock.results[0].value) as string;

      expect(value.split("")).not.toContain("&");
      expect(value.split("?")[1].split("=")[0]).toStrictEqual("redirect_uri");
    });

    test("returns the expected url", async () => {
      await NO_DEFAULT_IDAAS_CLIENT.signUp({ redirectUri: TEST_REDIRECT_URI });

      expect(await spyOnGenerateSignUpUrl.mock.results[0].value).toStrictEqual(
        `${TEST_BASE_URI}/api/web/user/onboard?redirect_uri=${encodeURIComponent(TEST_REDIRECT_URI)}`,
      );
    });
  });

  describe("sign up when `popup` is true", () => {
    // @ts-ignore wrong return type
    spyOn(browser, "openPopup").mockImplementation(() => "test");
    spyOn(browser, "listenToOnboardingPopup").mockResolvedValue(TEST_ONBOARDING_RESPONSE);

    test("returns the userId from the onboarding response", async () => {
      const result = await NO_DEFAULT_IDAAS_CLIENT.signUp({ popup: true });
      expect(result).toStrictEqual(TEST_USER_ID);
    });
  });

  describe("sign up when `popup` is false", () => {
    test("redirects to the url from generateSignUpUrl", async () => {
      await NO_DEFAULT_IDAAS_CLIENT.signUp();
      expect(window.location.href).toStrictEqual((await spyOnGenerateSignUpUrl.mock.results[0].value) as string);
    });

    test("returns null", async () => {
      const result = await NO_DEFAULT_IDAAS_CLIENT.signUp();
      expect(result).toBeNull();
    });
  });
});
