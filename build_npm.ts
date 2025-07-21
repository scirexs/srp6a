import { build, emptyDir } from "jsr:@deno/dnt";
import packageInfo from "./deno.json" with { type: "json" };

await emptyDir("./npm");

// const file = "./src/shared/functions.ts";
// let ts = await Deno.readTextFile(file);
// ts = ts.split("\n").slice(0, -7).join("\n");
// await Deno.writeTextFile(file, ts);

await build({
  entryPoints: [
    {
      name: "./client",
      path: "./src/client/mod.ts",
    },
    {
      name: "./server",
      path: "./src/server/mod.ts",
    },
  ],
  outDir: "./npm",
  scriptModule: false,
  typeCheck: false,
  declaration: "separate",
  test: false,
  shims: {
    deno: false,
  },
  compilerOptions: {
    lib: ["ES2023"],
    target: "ES2023",
  },
  package: {
    name: "@scirexs/srp6a",
    version: packageInfo.version,
    description: "SRP-6a (Secure Remote Password) implementation in TypeScript for browser and server.",
    author: "scirexs",
    license: "MIT",
    repository: {
      type: "git",
      url: "git+https://github.com/scirexs/srp6a.git"
    },
    keywords: [
      "authentication",
      "srp",
      "srp6a",
      "secure-remote-password",
      "typescript",
    ],
    homepage: "https://github.com/scirexs/srp6a#readme",
    bugs: {
      url: "https://github.com/scirexs/srp6a/issues"
    },
  },
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
  },
});
