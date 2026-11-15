// WCLI-158 AC0: a wired `ward` command whose tpm2 tool times out. It sets up a
// vault on the Linux backend with fake tools, then makes tpm2_unseal hang and
// runs `ward doctor`. It never calls process.exit itself, so it ends only when
// nothing keeps the event loop alive; it also reports whether the command
// asked for an explicit exit, as src/cli/ward.ts honours.
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { detectTpm2ForTest } from "../../src/adapters/tpm2-tools.ts";
import { runWard } from "../../src/cli/main.ts";
import { installFakeTools } from "./fake-tpm2/install.ts";

const [base, root] = process.argv.slice(2) as [string, string];
const bin = join(base, "bin");
const records = join(base, "records");
const checkout = join(base, "checkout");
mkdirSync(checkout, { recursive: true });
Bun.spawnSync(["git", "init", "-q", checkout]);

const presence = () =>
  detectTpm2ForTest(
    { path: bin, device: "/dev/null", openCheck: () => undefined },
    { trustRoot: root },
  );
const options = (timeoutMs: number) => ({
  wardDirectory: join(base, ".ward"),
  cwd: checkout,
  keySelection: {
    platform: "linux",
    tpm2: { detect: presence, timeoutMs },
  },
});

installFakeTools(bin, records, {});
const setup = await runWard(["setup", "--json"], options(10_000));
if (setup.exitCode !== 0) {
  console.log(`setup failed ${setup.stderr}`);
  process.exit(1);
}
installFakeTools(bin, records, { tpm2_unseal: "grandchild-hang" });
const doctor = await runWard(["doctor", "--json"], options(1_500));
const checks = (
  JSON.parse(doctor.stdout) as {
    data: { checks: { check: string; code: string }[] };
  }
).data.checks;
console.log(
  `doctor key=${checks.find((entry) => entry.check === "key_provider")?.code}`,
);
// A PROPAGATING command: backup does not fold the refusal into a report, so the
// timeout reaches runWard's catch (WCLI-158, #341 round 2).
const backup = await runWard(
  ["backup", "--output", join(base, "out.ward-backup"), "--json"],
  {
    ...options(1_500),
    passphrases: {
      available: () => true,
      read: () => new TextEncoder().encode("synthetic-passphrase"),
    },
  },
);
console.log(
  `backup explicit=${String(backup.exitExplicitly)} code=${(JSON.parse(backup.stderr.trim().split("\n").pop() ?? "{}") as { code?: string }).code}`,
);
console.log(`done explicit=${String(doctor.exitExplicitly)}`);
