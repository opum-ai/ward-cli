// Creates a GitHub Release for an existing tag and attaches files to it, using
// only the REST API (WCLI-82). The self-hosted runner has no `gh`, and a
// third-party release action would run with contents: write.
//
// The release is created as a draft, the assets are uploaded, and only then is
// it published, so a failed upload never leaves a public Release with missing
// files. The tag must already exist: the API would otherwise create it from the
// default branch, which is not what a release of a reviewed SHA means.
//
// Usage: node scripts/publish-release.mjs <notes-file> <asset>...
// Environment: GH_TOKEN, REPO (owner/name), TAG, GITHUB_API_URL (the runner sets
// it). Exit 0 with the Release URL on stdout; exit 1 naming the step that failed.
import { readFileSync } from "node:fs";
import { basename } from "node:path";

const { GH_TOKEN, REPO, TAG } = process.env;
const api = (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(
  /\/$/,
  "",
);
const [notesFile, ...assets] = process.argv.slice(2);

function fail(message) {
  console.error(`::error::publish-release: ${message}`);
  process.exit(1);
}

if (!GH_TOKEN || !REPO || !TAG) fail("GH_TOKEN, REPO and TAG must be set");
if (notesFile === undefined || assets.length === 0)
  fail("usage: publish-release.mjs <notes-file> <asset>...");

async function call(step, method, url, init = {}) {
  const response = await fetch(url, {
    method,
    ...init,
    headers: {
      Authorization: `Bearer ${GH_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...init.headers,
    },
  });
  if (!response.ok)
    fail(`${step}: ${method} ${url} answered ${response.status}`);
  return response.json();
}

await call(
  "the tag must already exist",
  "GET",
  `${api}/repos/${REPO}/git/ref/tags/${TAG}`,
);

const release = await call(
  "create the draft",
  "POST",
  `${api}/repos/${REPO}/releases`,
  {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tag_name: TAG,
      name: `Ward ${TAG}`,
      body: readFileSync(notesFile, "utf8"),
      draft: true,
      prerelease: false,
    }),
  },
);

const uploadUrl = String(release.upload_url).replace(/\{.*$/, "");
for (const asset of assets) {
  await call(
    `upload ${basename(asset)}`,
    "POST",
    `${uploadUrl}?name=${encodeURIComponent(basename(asset))}`,
    {
      headers: { "Content-Type": "application/octet-stream" },
      body: readFileSync(asset),
    },
  );
}

const published = await call(
  "publish the draft",
  "PATCH",
  `${api}/repos/${REPO}/releases/${release.id}`,
  {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ draft: false }),
  },
);
console.log(
  published.html_url ?? `${api}/repos/${REPO}/releases/${release.id}`,
);
