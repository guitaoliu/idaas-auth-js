export const createRandomString = () => {
  const randomNumbers = window.crypto.getRandomValues(new Uint8Array(32));

  return String.fromCharCode(...randomNumbers);
};

export const base64UrlStringEncode = (randomNumbers: string) => {
  return btoa(randomNumbers).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const base64UrlBufferEncode = (arrayBuffer: Uint8Array) => {
  return base64UrlStringEncode(String.fromCharCode(...new Uint8Array(arrayBuffer)));
};

export const generateChallengeVerifierPair = async () => {
  const randomString = createRandomString();
  const codeVerifier = base64UrlStringEncode(randomString);
  const codeChallenge = await createCodeChallenge(randomString);

  return { codeVerifier, codeChallenge };
};

export const sha256 = async (string: string) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(string);
  const hash = await window.crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
};

// biome-ignore lint/suspicious/noExplicitAny: dynamic object creation
export const keysToCamel = (object: any) => {
  // biome-ignore lint/suspicious/noExplicitAny: dynamic object creation
  const newObject = {} as any;

  if (typeof object === "object" && object !== null) {
    for (const key of Object.keys(object)) {
      newObject[toCamelCase(key)] = object[key];
    }
  }
  return newObject;
};

const toCamelCase = (value: string): string => {
  return value.replace(/(_\w)/g, (match) => match[1].toUpperCase());
};

const createCodeChallenge = async (randomString: string) => {
  const hash = await sha256(randomString);
  const base64Url = base64UrlBufferEncode(hash);
  return base64Url;
};
