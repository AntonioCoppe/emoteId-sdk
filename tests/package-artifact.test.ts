import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("package artifact shape", () => {
  it("points package metadata at the split SDK repo", () => {
    const packageJson = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8")) as {
      version: string;
      repository?: { url?: string };
      homepage?: string;
      bugs?: { url?: string };
    };

    expect(packageJson.version).toBe("0.1.2");
    expect(packageJson.repository?.url).toContain("AntonioCoppe/emoteId-sdk");
    expect(packageJson.homepage).toContain("AntonioCoppe/emoteId-sdk");
    expect(packageJson.bugs?.url).toContain("AntonioCoppe/emoteId-sdk/issues");
  });

  it("keeps the built ESM entrypoint on explicit .js imports", () => {
    const entryPath = existsSync(join(process.cwd(), "dist/index.js"))
      ? join(process.cwd(), "dist/index.js")
      : join(process.cwd(), "src/index.ts");
    const entryContents = readFileSync(entryPath, "utf8");

    expect(entryContents).toContain('./schema.js');
    expect(entryContents).not.toContain('from "./schema";');
  });
});
