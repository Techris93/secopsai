// Map the Workers runtime module to a local stub for Node's test runner.
export async function resolve(specifier, context, next) {
  if (specifier === "cloudflare:workers") {
    return { url: new URL("./cloudflare-workers-stub.mjs", import.meta.url).href, shortCircuit: true };
  }
  return next(specifier, context);
}
