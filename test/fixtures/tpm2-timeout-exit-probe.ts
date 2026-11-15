// WCLI-158: a probe that times a tool out and then does nothing else. It never
// calls process.exit, so it ends only when nothing keeps the event loop alive.
// The tool leaves a grandchild holding its pipes open; the timeout must kill it
// with the tool.
import { detectTpm2ForTest, runTool } from "../../src/adapters/tpm2-tools.ts";
import { installFakeTools } from "./fake-tpm2/install.ts";

const [bin, records, root] = process.argv.slice(2) as [string, string, string];
installFakeTools(bin, records, { tpm2_unseal: "grandchild-hang" });
const presence = detectTpm2ForTest(
  { path: bin, device: "/dev/null", openCheck: () => undefined },
  { trustRoot: root },
);
const reason = await runTool(presence, "tpm2_unseal", [], {
  timeoutMs: 1_500,
}).catch((error: { reason?: string }) => error.reason);
console.log(`done ${String(reason)}`);
