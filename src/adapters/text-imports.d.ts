// Text imports (`with { type: "text" }`) resolve to the file's contents as a
// string under Bun's bundler, which is how the packaged skill reaches the
// binary (src/adapters/skill-content.ts). TypeScript needs the module shape
// declared; runtime resolution is the bundler's.
declare module "*.md" {
  const text: string;
  export default text;
}
