#!/usr/bin/env node
// Every installed web dependency must carry an OSI-approved licence. Run it after `pnpm install`.
import { execFileSync } from "node:child_process"

const OSI = new Set([
  "MIT",
  "MIT-0",
  "ISC",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
  "OFL-1.1",
  "MPL-2.0",
  "CC0-1.0",
  "Unlicense",
  "Zlib",
  "BSL-1.0",
  "BlueOak-1.0.0",
  "Python-2.0",
  "CC-BY-4.0",
])
const COPYLEFT = /^(LGPL|GPL|AGPL)-/

function allowedTerm(term) {
  const t = term
    .trim()
    .replace(/\+$/, "")
    .replace(/ WITH .*/, "")
  return OSI.has(t) || COPYLEFT.test(t)
}

// "(MIT OR Apache-2.0)": one alternative is enough; "A AND B": every part is needed.
function allowed(expression) {
  return expression
    .replace(/[()]/g, "")
    .split(/\s+OR\s+/)
    .some((alternative) => alternative.split(/\s+AND\s+/).every(allowedTerm))
}

const out = execFileSync("pnpm", ["licenses", "list", "--json"], {
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
})
const bad = []
for (const [licence, packages] of Object.entries(JSON.parse(out))) {
  if (allowed(licence)) continue
  for (const pkg of packages) bad.push(`${pkg.name}@${(pkg.versions ?? []).join(",")}: ${licence}`)
}

if (bad.length) {
  for (const line of bad) console.error(line)
  process.exit(1)
}
console.log("licences ok")
