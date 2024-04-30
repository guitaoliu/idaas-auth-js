export const formatIssuerUrl = (issuerUrl: string): string => {
  // remove trailing /
  const url = issuerUrl.endsWith("/") ? issuerUrl.slice(0, -1) : issuerUrl;
  // prepend https:// if it's not already there
  return url.startsWith("https://") ? url : `https://${url}`;
};
