// Asserts that the release tag is an annotated tag, from the ref GitHub
// stores rather than from what the checkout left in the working tree (WCLI-82
// review, finding 3).
//
// `git cat-file -t refs/tags/<tag>` answers from whatever refs the checkout
// fetched, and that is the part this check was resting on rather than
// proving: actions/checkout resolves a tag ref to its commit, and for an
// annotated tag the object it can end up asking for is the commit, so a
// correctly cut annotated tag can read as lightweight and fail the build —
// after the tag is pushed, which is the failure class F2 was about. The REST
// ref names the object the tag actually is, so the answer does not depend on
// the checkout at all.
//
// This is the same read `scripts/publish-release.mjs` already makes with the
// job token, and it needs no permission the build job lacks: reading a git ref
// is covered by `contents: read`.
//
// Usage: node scripts/check-release-tag.mjs
// Environment: GH_TOKEN, REPO (owner/name), TAG, GITHUB_API_URL (the runner
// sets it). Exit 0 when the ref is a tag object; exit 1 naming what it found.
const { GH_TOKEN, REPO, TAG } = process.env;
const api = (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(
  /\/$/,
  "",
);

function fail(message) {
  console.error(`::error::check-release-tag: ${message}`);
  process.exit(1);
}

if (!GH_TOKEN || !REPO || !TAG) fail("GH_TOKEN, REPO and TAG must be set");

const response = await fetch(`${api}/repos/${REPO}/git/ref/tags/${TAG}`, {
  headers: {
    Authorization: `Bearer ${GH_TOKEN}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  },
});
if (!response.ok)
  fail(
    `could not read refs/tags/${TAG} (HTTP ${response.status}); the tag must already exist`,
  );

const { object } = await response.json();
if (object?.type !== "tag")
  fail(
    `${TAG} is not an annotated tag: its ref names a ${object?.type ?? "missing object"}, not a tag. Cut it with git tag -a`,
  );

console.log(`${TAG} is an annotated tag object ${object.sha}`);
