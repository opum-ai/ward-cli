// Built by test/launcher.test.ts through scripts/build.ts, so it carries the
// shipped executable's flags. Ward itself reads no environment variable that
// would make a loaded .env observable, so this probe reports on the runtime
// directly: the names only, never a value.
const names = process.argv.slice(2);
process.stdout.write(
  `${JSON.stringify(names.filter((name) => name in process.env))}\n`,
);
