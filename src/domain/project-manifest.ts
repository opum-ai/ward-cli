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
//
// Profile declarations are the one deliberate exception, and it is scoped.
// The `profiles` object must be an object of bounded size, but each
// declaration inside it is carried as the manifest wrote it and validated by
// `normalizeProfile` where that profile is used (WCLI-9). A declaration this
// build cannot read therefore refuses the profile that carries it and
// nothing else — a profile written for a newer Ward must not take
// `ward secret` down with it, which is what validating the whole manifest at
// once would do.
import { WardError } from "../contract/errors.ts";
import { isOpaqueId } from "./identifiers.ts";
import { profileLimits } from "./profile.ts";

export const projectManifestSchemaVersion = 1;

export interface ProjectManifest {
  readonly schemaVersion: number;
  readonly projectId: string;
  // Profile declarations exactly as the manifest declared them, keyed by
  // name. Nothing here has been normalized or trusted.
  readonly profiles: Readonly<Record<string, unknown>>;
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
  if (
    typeof profiles !== "object" ||
    profiles === null ||
    Array.isArray(profiles)
  )
    throw new WardError("project_manifest_malformed");
  const entries = Object.entries(profiles as Record<string, unknown>);
  // Bounded here because this object is what every profile command walks;
  // whether a declaration is usable is decided where it is used.
  if (entries.length > profileLimits.maxProfilesPerManifest)
    throw new WardError("project_manifest_malformed");
  for (const [name] of entries)
    if (name.length === 0 || name.length > profileLimits.maxProfileNameChars)
      throw new WardError("project_manifest_malformed");
  return {
    schemaVersion: projectManifestSchemaVersion,
    projectId: document.projectId,
    profiles: Object.fromEntries(entries),
  };
}

// Written with a trailing newline, so the file is a normal text file in a
// repository diff. Profile declarations are carried through as they were
// read: this function writes a new manifest (creation or restore), and a
// rewrite of an existing one would otherwise be a way to drop profiles
// nobody asked it to touch.
export function serializeProjectManifest(manifest: ProjectManifest): string {
  return `${JSON.stringify(
    {
      schemaVersion: projectManifestSchemaVersion,
      projectId: manifest.projectId,
      profiles: manifest.profiles,
    },
    null,
    2,
  )}\n`;
}
