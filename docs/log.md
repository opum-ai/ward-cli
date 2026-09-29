# Change log

## docs

- 2026-09-27T20:48:21-05:00 39834d524102e06439f0b1b65c861893434c4f7c Adopt ward-cli into the Opum fleet (OPAG-655)
- 2026-09-28T12:12:02-05:00 65a87b5cc6d9c7dfe2975dc2a33735acdeb1e38e WCLI-3: ADRs for storage and key custody, threat model, profile authority (#12)
- 2026-09-28T13:11:04-05:00 c41a62af265c62853a75b929713b7c0d34cc7e63 WCLI-23: record the committed platform target (ODOC-316) (#16)
- 2026-09-28T18:16:01-05:00 a1c8d29633574a01f286fd88eb76514e1810c6a8 WCLI-7: `ward init` and project binding (#27)
- 2026-09-28T18:25:49-05:00 4ed62db68c4fab55c58b2c15be589945a936a653 WCLI-28: track the lore-generated bundle index and log (#31)
- 2026-09-28T19:14:02-05:00 3dfe16aea0999900c69d6f3aeccc92b3b6de847d WCLI-13: encrypted backup and fresh-store restore (#32)
- 2026-09-28T20:00:23-05:00 d0b8877cbff67cd301cc20c8b188c5f22e57269e WCLI-26: `ward status` and `ward doctor` (#36)
- 2026-09-28T20:21:13-05:00 53fbbc8b311297ea2cf03380666d7038cbb6435e WCLI-25: keep the four lore agent source lists current
- 2026-09-28T20:52:05-05:00 3e4064729f20950cd2ac783798994979297657a5 WCLI-25: keep the four lore agent source lists current (#43)
- 2026-09-29T01:11:17-05:00 c4c646df5b692b4ef486202889881399ee63705d docs(WCLI-10): record the transport decision as ADR 0009
- 2026-09-29T01:22:37-05:00 58d0604c5bfe2d3863aa8b10fe2e3368371b53a9 WCLI-10: the status-only HTTPS transport (#67)
- 2026-09-29T06:16:11-05:00 d187fe72b23e17ce94b270b3b5df1ad472933ffc WCLI-11: vault state format 2, the full audit field set, and the refusal that replaces recovery (#93)
- 2026-09-29T06:50:14-05:00 537c23e55cbfd5e0574171774e13441199ff5f7e refactor(WCLI-51): one vault format at version 1, no compatibility surface
- 2026-09-29T07:02:08-05:00 61aa8a24d6818fcdc852bddfb5267252e83f4161 refactor(WCLI-51): one vault format at version 1, no compatibility surface (#99)
- 2026-09-29T09:40:58-05:00 dc85a77e53e3a60b8c38f67f4582793e0a903fd7 fix(WCLI-52): refuse a backup of a state document that does not parse
- 2026-09-29T09:50:54-05:00 74015e86f9756e2747f21fc80cbced849596d1cb fix(WCLI-52): answer the review — make the output assertion measure, and the second code
- 2026-09-29T09:58:00-05:00 e08c848d9bc770321a5f88469280fb777b89a618 fix(WCLI-52): refuse a backup of a state document that does not parse (#110)
- 2026-09-29T10:32:41-05:00 e54539439299847ac8adad9b925ea3d9fa26cdaa test(WCLI-53): assert the store-call bound instead of waiting it out (#112)
- 2026-09-29T10:38:14-05:00 8fc98a1437d51b987515ad56cab7a9d9335cd415 chore(WCLI-58): handoff note on recycle at the WCLI-53 / WCLI-14 boundary (#114)
- 2026-09-29T11:27:32-05:00 9c54c5cebd7595eb63bfbdd8f9d16669e4a76aa2 docs(WCLI-14): record DEC-44 and DEC-45, and correct the spec where they land (#121)
- 2026-09-29T11:59:04-05:00 351ff7e05c6d90a36ab92bef0a5779ee9d07d80f feat(WCLI-46): reclaim stale test roots with an explicit clean:temp (DEC-49) (#127)
- 2026-09-29T12:13:18-05:00 8b2a588098c85b75b69b74c0d861a4ac143040d7 feat(WCLI-14): skill-file drift and the init multiselect, with DEC-46..52 recorded (#128)
- 2026-09-29T12:18:06-05:00 55fa91fe57c77eaf7e0757a7b86a46957e35d21e docs(WCLI-38): bump profileSnapshotVersion at the first release (DEC-50) (#129)
- 2026-09-29T12:23:49-05:00 e7bec34e97d663a4f94538d3e475e78e20721314 docs(WCLI-30): point the bundle at the spec of record (DEC-51) (#130)
- 2026-09-29T13:04:42-05:00 c0f48a154798793b799479ec1c91ba0ee9852068 docs(WCLI-61): record DEC-56 — the spec pointer keeps its two sections (#132)
- 2026-09-29T13:39:21-05:00 45b68a35ee3433eee99c5d82c098c20b1f8172e8 docs(WCLI-63): carry DEC-38's deferred compatibility question in the release runbook

## docs/adr

- 2026-09-28T13:09:30-05:00 e46ae0c8607368ac036a0f1fbcfc3a053b9fa7c3 WCLI-5: KeyProvider with a bounded macOS Keychain adapter (#15)
- 2026-09-28T14:43:48-05:00 8bd61d107fc98171d3cb852bf0800b1c03405a9f WCLI-6: encrypted SQLite snapshot store with transactional mutation (#19)
- 2026-09-28T15:59:49-05:00 9709d912bd155500422d0514005077c2d7817a49 WCLI-20: ward setup with serialized key creation and crash resume (#21)
- 2026-09-28T22:30:27-05:00 51f000ee586268f4241dbe5d54ca2bf805038323 WCLI-32: scope ADR 0001's vault_busy claim, and file WCLI-31 (#53)
