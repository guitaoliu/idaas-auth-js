import { afterAll, afterEach, describe, expect, jest, spyOn, test } from "bun:test";
import type { LoginOptions } from "../../src";
import { NO_DEFAULT_IDAAS_CLIENT, TEST_ACR_CLAIM, TEST_ID_TOKEN_OBJECT } from "../constants";

describe("IdaasClient.isAcrDesired", () => {
  afterAll(() => {
    jest.restoreAllMocks();
  });

  afterEach(() => {
    localStorage.clear();
    jest.clearAllMocks();
  });

  // @ts-ignore private method
  const spyOnGetIdTokenAcr = spyOn(NO_DEFAULT_IDAAS_CLIENT, "getIdTokenAcr");
  // @ts-ignore private method
  const spyOnisIncluded = spyOn(NO_DEFAULT_IDAAS_CLIENT, "isIncluded");
  const spyOnLogin = spyOn(NO_DEFAULT_IDAAS_CLIENT, "login").mockImplementation(async () => {
    // @ts-ignore private method
    await NO_DEFAULT_IDAAS_CLIENT.persistenceManager.saveIdToken(TEST_ID_TOKEN_OBJECT);
    return null;
  });

  test("getIdTokenAcr is called", async () => {
    spyOnGetIdTokenAcr.mockImplementationOnce(async () => TEST_ACR_CLAIM);
    await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM] });

    expect(spyOnGetIdTokenAcr).toBeCalled();
  });

  test("getIdTokenAcr returns the stored ID token's acr claim", async () => {
    // @ts-ignore private method
    NO_DEFAULT_IDAAS_CLIENT.persistenceManager.saveIdToken(TEST_ID_TOKEN_OBJECT);
    await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM] });

    expect(spyOnGetIdTokenAcr.mock.results[0].value).toStrictEqual(TEST_ACR_CLAIM);
  });

  test("getIdTokenAcr returns undefined if no acr claim on stored ID token", async () => {
    // @ts-ignore private method
    NO_DEFAULT_IDAAS_CLIENT.persistenceManager.saveIdToken({ ...TEST_ID_TOKEN_OBJECT, decoded: {} });
    await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM] });

    expect(spyOnGetIdTokenAcr.mock.results[0].value).toBeUndefined();
  });

  test("getIdTokenAcr returns undefined if no ID token stored", async () => {
    // @ts-ignore private method
    await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM] });

    expect(spyOnGetIdTokenAcr.mock.results[0].value).toBeUndefined();
  });

  test("isIncluded is called", async () => {
    spyOnisIncluded.mockImplementationOnce(async () => true);
    await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM] });

    expect(spyOnisIncluded).toBeCalled();
  });

  test("isIncluded returns true if currentAcr is included in desiredAcr", async () => {
    // @ts-ignore private method
    NO_DEFAULT_IDAAS_CLIENT.persistenceManager.saveIdToken(TEST_ID_TOKEN_OBJECT);
    await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM, "different"] });

    expect(spyOnisIncluded.mock.results[0].value).toBeTrue();
  });

  test("isIncluded returns false if currentAcr is not included in desiredAcr", async () => {
    // @ts-ignore private method
    NO_DEFAULT_IDAAS_CLIENT.persistenceManager.saveIdToken(TEST_ID_TOKEN_OBJECT);
    await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: ["different", "differenter"] });

    expect(spyOnisIncluded.mock.results[0].value).toBeFalse();
  });

  test("isIncluded returns false if currentAcr is undefined", async () => {
    // @ts-ignore private method
    NO_DEFAULT_IDAAS_CLIENT.persistenceManager.saveIdToken({ ...TEST_ID_TOKEN_OBJECT, decoded: {} });
    await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM] });

    expect(spyOnisIncluded.mock.results[0].value).toBeFalse();
  });

  test.each([true, false])(
    "returns the result of isIncluded if fallbackAuthorization is not specified",
    async (value) => {
      spyOnisIncluded.mockImplementationOnce(() => value);
      const result = await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM] });

      expect(spyOnisIncluded.mock.calls.length).toStrictEqual(1);
      expect(result).toBe(value);
    },
  );

  describe("fallbackAuthorization specified", () => {
    test("returns true if isIncluded without calling login", async () => {
      // @ts-ignore private method
      NO_DEFAULT_IDAAS_CLIENT.persistenceManager.saveIdToken(TEST_ID_TOKEN_OBJECT);
      const result = await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({
        desiredAcr: [TEST_ACR_CLAIM],
        fallbackAuthorization: {},
      });
      const expected = spyOnisIncluded.mock.results[0].value as boolean;

      expect(spyOnisIncluded.mock.calls.length).toStrictEqual(1);
      expect(result).toBe(expected);
      expect(spyOnLogin).not.toBeCalled();
    });

    describe("isIncluded is false", () => {
      test("calls login", async () => {
        await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM], fallbackAuthorization: {} });

        expect(spyOnLogin).toBeCalled();
      });

      test("login call contains the desiredAcr", async () => {
        await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({
          desiredAcr: [TEST_ACR_CLAIM, "different"],
          fallbackAuthorization: {},
        });

        const call = spyOnLogin.mock.calls[0][0] as LoginOptions;

        expect(call.acrValues).toStrictEqual([TEST_ACR_CLAIM, "different"]);
      });

      test("isIncluded is called again after login", async () => {
        await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({ desiredAcr: [TEST_ACR_CLAIM], fallbackAuthorization: {} });

        const loginOrder = spyOnLogin.mock.invocationCallOrder;
        const desiredOrder = spyOnisIncluded.mock.invocationCallOrder;

        expect(loginOrder[loginOrder.length - 1]).toBeLessThan(desiredOrder[desiredOrder.length - 1]);
        expect(spyOnisIncluded).toBeCalledTimes(2);
      });

      describe("returns the value of the second isIncluded call", () => {
        test("returns true", async () => {
          const result = await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({
            desiredAcr: [TEST_ACR_CLAIM],
            fallbackAuthorization: {},
          });
          const expected = spyOnisIncluded.mock.results[1].value as boolean;

          expect(result).toBe(expected);
        });

        test("returns false", async () => {
          spyOnLogin.mockImplementation(() => null);
          const result = await NO_DEFAULT_IDAAS_CLIENT.isAcrDesired({
            desiredAcr: [TEST_ACR_CLAIM],
            fallbackAuthorization: {},
          });
          const expected = spyOnisIncluded.mock.results[1].value as boolean;

          expect(result).toBe(expected);
        });
      });
    });
  });
});
