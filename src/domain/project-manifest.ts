// The tracked project manifest, `<repository>/.ward/project.json` (spec
// §6.1, §9.1). It is repository-controlled: the file is committed, anyone
// who can edit the repository can edit it, and it is therefore a request,
// never authority (docs/adr/0003). It carries an opaque project id and
// non-secret profile declarations, so the id can be read out of a copied
// checkout — which is exactly why the binding that grants access lives in
// the encrypted vault and names a canonical worktree root instead (§7.1).
//
// Fields are validated on read and unknown keys are refused: a manifest this
// build cannot interpret is a manifest it must not act on.
import { WardError } from "../contract/errors.ts";
import { isOpaqueId } from "./identifiers.ts";

export const projectManifestSchemaVersion = 1;

export interface ProjectManifest {
  readonly schemaVersion: number;
  readonly projectId: string;
  // Profile declarations are spec §9.1's next contract (WCLI-9). This build
  // writes the key and refuses any entry, so a manifest carrying profiles is
  // read by the build that defines them, not guessed at by this one.
  readonly profiles: Readonly<Record<string, never>>;
}

export function newProjectManifest(projectId: string): ProjectManifest {
  return {
    schemaVersion: projectManifestSchemaVersion,
    projectId,
    profiles: {},
  };
}

export function parseProjectManifest(text: string): ProjectManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new WardError("project_manifest_malformed");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    throw new WardError("project_manifest_malformed");
  const document = parsed as Record<string, unknown>;
  for (const key of Object.keys(document))
    if (key !== "schemaVersion" && key !== "projectId" && key !== "profiles")
      throw new WardError("project_manifest_unsupported");
  if (document.schemaVersion !== projectManifestSchemaVersion)
    throw new WardError("project_manifest_unsupported");
  if (!isOpaqueId(document.projectId))
    throw new WardError("project_manifest_malformed");
  const profiles = document.profiles ?? {};
  const keys =
    typeof profiles === "object" &&
    profiles !== null &&
    !Array.isArray(profiles)
      ? Object.keys(profiles)
      : undefined;
  if (keys === undefined || keys.length > 0)
    throw new WardError("project_manifest_unsupported");
  return {
    schemaVersion: projectManifestSchemaVersion,
    projectId: document.projectId,
    profiles: {},
  };
}

// Written with a trailing newline, so the file is a normal text file in a
// repository diff.
export function serializeProjectManifest(manifest: ProjectManifest): string {
  return `${JSON.stringify(
    {
      schemaVersion: projectManifestSchemaVersion,
      projectId: manifest.projectId,
      profiles: {},
    },
    null,
    2,
  )}\n`;
}
