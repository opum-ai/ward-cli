// scripts/publish-release.mjs against a mock GitHub API (WCLI-82). The real
// call needs a token and a tag, so what is pinned here is the order and the
// refusals: the tag must exist before anything is created, a Release is a draft
// until every asset is attached, and a failed step never publishes.
import { afterAll, expect, test } from "bun:test";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { createTempRoot } from "./support/temp-root.ts";

const script = join(import.meta.dir, "..", "scripts", "publish-release.mjs");
const dir = createTempRoot("ward-publish-");
const notes = join(dir, "notes.md");
const assetA = join(dir, "ward-darwin-arm64");
const assetB = join(dir, "ward-darwin-arm64.sha256");
writeFileSync(notes, "notes\n");
writeFileSync(assetA, "binary");
writeFileSync(assetB, "hash  ward-darwin-arm64\n");

type Call = { method: string; path: string; body: string };

// `fail` names the step the mock answers 500 or 404 for.
function mock(fail?: "tag" | "upload") {
  const calls: Call[] = [];
  const server: ReturnType<typeof Bun.serve> = Bun.serve({
    port: 0,
    async fetch(request): Promise<Response> {
      const url = new URL(request.url);
      const body = await request.text();
      calls.push({
        method: request.method,
        path: url.pathname + url.search,
        body,
      });
      if (request.headers.get("authorization") !== "Bearer synthetic-token")
        return new Response("no", { status: 401 });
      if (request.method === "GET")
        return fail === "tag"
          ? new Response("{}", { status: 404 })
          : Response.json({ ref: "refs/tags/v0.1.0" });
      if (request.method === "POST" && url.pathname.endsWith("/releases"))
        return Response.json({
          id: 7,
          upload_url: `http://localhost:${server.port}/uploads/7/assets{?name,label}`,
        });
      if (request.method === "POST")
        return fail === "upload"
          ? new Response("{}", { status: 500 })
          : Response.json({});
      return Response.json({ html_url: "https://example.invalid/releases/7" });
    },
  });
  afterAll(() => server.stop(true));
  return { server, calls };
}

async function publish(server: { port: number | undefined }) {
  const child = Bun.spawn(["node", script, notes, assetA, assetB], {
    env: {
      PATH: process.env.PATH ?? "",
      GH_TOKEN: "synthetic-token",
      REPO: "opum-ai/ward-cli",
      TAG: "v0.1.0",
      GITHUB_API_URL: `http://localhost:${server.port}`,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [out, err, status] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { out, err, status };
}

test("checks the tag, drafts, uploads both assets, then publishes", async () => {
  const { server, calls } = mock();
  const r = await publish(server);
  expect(r.status).toBe(0);
  expect(r.out.trim()).toBe("https://example.invalid/releases/7");
  expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
    "GET /repos/opum-ai/ward-cli/git/ref/tags/v0.1.0",
    "POST /repos/opum-ai/ward-cli/releases",
    "POST /uploads/7/assets?name=ward-darwin-arm64",
    "POST /uploads/7/assets?name=ward-darwin-arm64.sha256",
    "PATCH /repos/opum-ai/ward-cli/releases/7",
  ]);
  expect(JSON.parse(calls[1]?.body ?? "{}").draft).toBe(true);
  expect(JSON.parse(calls[4]?.body ?? "{}").draft).toBe(false);
});

test("a tag that does not exist creates nothing", async () => {
  const { server, calls } = mock("tag");
  const r = await publish(server);
  expect(r.status).toBe(1);
  expect(r.err).toContain("the tag must already exist");
  expect(calls.length).toBe(1);
});

test("a failed upload is named and the draft is never published", async () => {
  const { server, calls } = mock("upload");
  const r = await publish(server);
  expect(r.status).toBe(1);
  expect(r.err).toContain("upload ward-darwin-arm64");
  expect(calls.some((c) => c.method === "PATCH")).toBe(false);
});
