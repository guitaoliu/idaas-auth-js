import testSpa from "./index.html";

const staticServer = Bun.serve({
  port: 8080,
  static: {
    "/": testSpa,
  },
  async fetch(req) {
    const url = new URL(req.url);

    console.info(req.method, url.pathname);

    return new Response();
  },
});

console.log("🚀", staticServer.url.origin);
