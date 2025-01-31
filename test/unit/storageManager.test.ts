import { afterEach, describe, expect, test } from "bun:test";
import { type AccessToken, StorageManager } from "../../src/storage/StorageManager";
import {
  TEST_ACCESS_TOKEN_KEY,
  TEST_ACCESS_TOKEN_OBJECT,
  TEST_CLIENT_ID,
  TEST_CLIENT_PARAMS,
  TEST_CLIENT_PARAMS_KEY,
  TEST_ID_TOKEN_KEY,
  TEST_ID_TOKEN_OBJECT,
  TEST_TOKEN_PARAMS,
  TEST_TOKEN_PARAMS_KEY,
} from "./constants";

describe("StorageManager", () => {
  const storageManager = new StorageManager(TEST_CLIENT_ID, "localstorage");

  afterEach(() => {
    localStorage.clear();
  });

  describe("access token storage", () => {
    describe("getAccessToken", () => {
      test("returns undefined if no tokens stored", () => {
        const result = storageManager.getAccessTokens();
        expect(result).toBeUndefined();
      });

      test("returns an array of tokens if a single token stored", () => {
        const value = [TEST_ACCESS_TOKEN_OBJECT];
        localStorage.setItem(TEST_ACCESS_TOKEN_KEY, JSON.stringify(value));

        const result = storageManager.getAccessTokens();
        expect(result).toStrictEqual(value);
      });

      test("returns an array of tokens if multiple tokens stored", () => {
        const value = new Array(3).fill(TEST_ACCESS_TOKEN_OBJECT);
        localStorage.setItem(TEST_ACCESS_TOKEN_KEY, JSON.stringify(value));

        const result = storageManager.getAccessTokens();
        expect(result).toStrictEqual(value);
      });
    });

    describe("removeAccessToken", () => {
      test("does nothing if no tokens stored", () => {
        const value: object[] = [];
        localStorage.setItem(TEST_ACCESS_TOKEN_KEY, JSON.stringify(value));

        expect(() => {
          storageManager.removeAccessToken(TEST_ACCESS_TOKEN_OBJECT);
        }).not.toThrowError();
      });

      test("removes the final token stored", () => {
        const value = [TEST_ACCESS_TOKEN_OBJECT];
        localStorage.setItem(TEST_ACCESS_TOKEN_KEY, JSON.stringify(value));

        storageManager.removeAccessToken(TEST_ACCESS_TOKEN_OBJECT);
        expect(localStorage.getItem(TEST_ACCESS_TOKEN_KEY)).toBe(JSON.stringify([]));
      });

      test("removes the correct token if multiple stored", () => {
        const token1: AccessToken = { ...TEST_ACCESS_TOKEN_OBJECT, accessToken: "123" };
        const token2: AccessToken = { ...TEST_ACCESS_TOKEN_OBJECT, accessToken: "321" };
        const value = [token1, token2];
        localStorage.setItem(TEST_ACCESS_TOKEN_KEY, JSON.stringify(value));

        storageManager.removeAccessToken(token2);
        expect(localStorage.getItem(TEST_ACCESS_TOKEN_KEY)).toStrictEqual(JSON.stringify([token1]));
      });
    });

    describe("saveAccessToken", () => {
      test("stores access token as an array if none already stored", () => {
        storageManager.saveAccessToken(TEST_ACCESS_TOKEN_OBJECT);
        expect(localStorage.getItem(TEST_ACCESS_TOKEN_KEY)).toStrictEqual(JSON.stringify([TEST_ACCESS_TOKEN_OBJECT]));
      });

      test("stores multiple tokens with different scopes, same audience", () => {
        const token1: AccessToken = { ...TEST_ACCESS_TOKEN_OBJECT, scope: "1" };
        const token2: AccessToken = { ...TEST_ACCESS_TOKEN_OBJECT, scope: "2" };

        storageManager.saveAccessToken(token1);
        expect(JSON.parse(localStorage.getItem(TEST_ACCESS_TOKEN_KEY) ?? "").length).toBe(1);

        storageManager.saveAccessToken(token2);
        expect(JSON.parse(localStorage.getItem(TEST_ACCESS_TOKEN_KEY) ?? "").length).toBe(2);
      });

      test("stores multiple tokens with different audience, same scopes", () => {
        const token1: AccessToken = { ...TEST_ACCESS_TOKEN_OBJECT, audience: "1" };
        const token2: AccessToken = { ...TEST_ACCESS_TOKEN_OBJECT, audience: "2" };

        storageManager.saveAccessToken(token1);
        expect(JSON.parse(localStorage.getItem(TEST_ACCESS_TOKEN_KEY) ?? "").length).toBe(1);

        storageManager.saveAccessToken(token2);
        expect(JSON.parse(localStorage.getItem(TEST_ACCESS_TOKEN_KEY) ?? "").length).toBe(2);
      });
    });
  });

  describe("token param storage", () => {
    describe("getTokenParams", () => {
      test("returns undefined if no token params stored", () => {
        expect(storageManager.getTokenParams()).toBeUndefined();
      });

      test("returns the stored token params", () => {
        localStorage.setItem(TEST_TOKEN_PARAMS_KEY, JSON.stringify(TEST_TOKEN_PARAMS));
        expect(storageManager.getTokenParams()).toStrictEqual(TEST_TOKEN_PARAMS);
      });
    });

    describe("removeTokenParams", () => {
      test("does nothing if no token params stored", () => {
        expect(() => {
          storageManager.removeTokenParams();
        }).not.toThrowError();
      });

      test("removes the stored token params", () => {
        localStorage.setItem(TEST_TOKEN_PARAMS_KEY, JSON.stringify(TEST_TOKEN_PARAMS));
        storageManager.removeTokenParams();
        expect(localStorage.getItem(TEST_TOKEN_PARAMS_KEY)).toBeNull();
      });
    });

    describe("saveTokenParams", () => {
      test("stores the given token params", () => {
        storageManager.saveTokenParams(TEST_TOKEN_PARAMS);
        expect(localStorage.getItem(TEST_TOKEN_PARAMS_KEY)).toStrictEqual(JSON.stringify(TEST_TOKEN_PARAMS));
      });
    });
  });
  describe("client param storage", () => {
    describe("getClientParams", () => {
      test("returns undefined if no client params stored", () => {
        expect(storageManager.getClientParams()).toBeUndefined();
      });

      test("returns the stored client params", () => {
        localStorage.setItem(TEST_CLIENT_PARAMS_KEY, JSON.stringify(TEST_CLIENT_PARAMS));
        const result = storageManager.getClientParams();
        expect(result).toStrictEqual(TEST_CLIENT_PARAMS);
      });
    });

    describe("saveClientParams", () => {
      test("stores the given client params", () => {
        storageManager.saveClientParams(TEST_CLIENT_PARAMS);
        expect(localStorage.getItem(TEST_CLIENT_PARAMS_KEY)).toStrictEqual(JSON.stringify(TEST_CLIENT_PARAMS));
      });
    });
  });

  describe("ID token storage", () => {
    describe("getIdToken", () => {
      test("returns undefined if no ID token stored", () => {
        expect(storageManager.getIdToken()).toBeUndefined();
      });

      test("returns the stored ID token", () => {
        localStorage.setItem(TEST_ID_TOKEN_KEY, JSON.stringify(TEST_ID_TOKEN_OBJECT));
        const result = storageManager.getIdToken();
        expect(result).toStrictEqual(TEST_ID_TOKEN_OBJECT);
      });
    });

    describe("saveIdToken", () => {
      test("stores the given ID token", () => {
        storageManager.saveIdToken(TEST_ID_TOKEN_OBJECT);
        expect(localStorage.getItem(TEST_ID_TOKEN_KEY)).toStrictEqual(JSON.stringify(TEST_ID_TOKEN_OBJECT));
      });
    });
  });

  test("remove() clears storage", () => {
    localStorage.setItem(TEST_TOKEN_PARAMS_KEY, JSON.stringify(TEST_TOKEN_PARAMS));
    localStorage.setItem(TEST_ACCESS_TOKEN_KEY, JSON.stringify(TEST_ACCESS_TOKEN_OBJECT));
    localStorage.setItem(TEST_ID_TOKEN_KEY, JSON.stringify(TEST_ID_TOKEN_OBJECT));
    localStorage.setItem(TEST_CLIENT_PARAMS_KEY, JSON.stringify(TEST_CLIENT_PARAMS));
    storageManager.remove();
    expect(localStorage.length).toBe(0);
  });
});
