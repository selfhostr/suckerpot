/**
 * The text of every page's "?" popover, in one place so it can be reviewed together.
 * Each text is two or three plain sentences: what the page shows, where its data comes from,
 * and one useful action. Never describe a feature the page does not have.
 */

import { tk } from "@/i18n"
import { withText } from "@/lib/utils"

export interface HelpText {
  /** Shown as the popover heading. */
  title: string
  body: string
}

export const HELP = {
  today: withText(
    { title: tk("help_today_title"), body: tk("help_today_body") },
    {},
  ),
  attacks: withText(
    { title: tk("help_attacks_title"), body: tk("help_attacks_body") },
    {},
  ),
  session: withText(
    { title: tk("help_session_title"), body: tk("help_session_body") },
    {},
  ),
  attackers: withText(
    { title: tk("help_attackers_title"), body: tk("help_attackers_body") },
    {},
  ),
  attacker: withText(
    { title: tk("help_attacker_title"), body: tk("help_attacker_body") },
    {},
  ),
  networks: withText(
    { title: tk("help_networks_title"), body: tk("help_networks_body") },
    {},
  ),
  patterns: withText(
    { title: tk("help_patterns_title"), body: tk("help_patterns_body") },
    {},
  ),
  campaigns: withText(
    { title: tk("help_campaigns_title"), body: tk("help_campaigns_body") },
    {},
  ),
  campaign: withText(
    { title: tk("help_campaign_title"), body: tk("help_campaign_body") },
    {},
  ),
  techniques: withText(
    { title: tk("help_techniques_title"), body: tk("help_techniques_body") },
    {},
  ),
  scripts: withText(
    { title: tk("help_scripts_title"), body: tk("help_scripts_body") },
    {},
  ),
  script: withText(
    { title: tk("help_script_title"), body: tk("help_script_body") },
    {},
  ),
  malware: withText(
    { title: tk("help_malware_title"), body: tk("help_malware_body") },
    {},
  ),
  sample: withText(
    { title: tk("help_sample_title"), body: tk("help_sample_body") },
    {},
  ),
  infrastructure: withText(
    { title: tk("help_infrastructure_title"), body: tk("help_infrastructure_body") },
    {},
  ),
  blocklists: withText(
    { title: tk("help_blocklists_title"), body: tk("help_blocklists_body") },
    {},
  ),
  "blocklists-network": withText(
    { title: tk("help_blocklists_network_title"), body: tk("help_blocklists_network_body") },
    {},
  ),
  detections: withText(
    { title: tk("help_detections_title"), body: tk("help_detections_body") },
    {},
  ),
  exposure: withText(
    { title: tk("help_exposure_title"), body: tk("help_exposure_body") },
    {},
  ),
  cves: withText(
    { title: tk("help_cves_title"), body: tk("help_cves_body") },
    {},
  ),
  "settings-alert-rules": withText(
    { title: tk("help_settings_alert_rules_title"), body: tk("help_settings_alert_rules_body") },
    {},
  ),
  report: withText(
    { title: tk("help_report_title"), body: tk("help_report_body") },
    {},
  ),
  abuse: withText(
    { title: tk("help_abuse_title"), body: tk("help_abuse_body") },
    {},
  ),
  "abuse-results": withText(
    { title: tk("help_abuse_results_title"), body: tk("help_abuse_results_body") },
    {},
  ),
  "abuse-target": withText(
    { title: tk("help_abuse_target_title"), body: tk("help_abuse_target_body") },
    {},
  ),
  "abuse-report": withText(
    { title: tk("help_abuse_report_title"), body: tk("help_abuse_report_body") },
    {},
  ),
  "settings-general": withText(
    { title: tk("help_settings_general_title"), body: tk("help_settings_general_body") },
    {},
  ),
  "settings-keys": withText(
    { title: tk("help_settings_keys_title"), body: tk("help_settings_keys_body") },
    {},
  ),
  "settings-users": withText(
    { title: tk("help_settings_users_title"), body: tk("help_settings_users_body") },
    {},
  ),
  "settings-audit": withText(
    { title: tk("help_settings_audit_title"), body: tk("help_settings_audit_body") },
    {},
  ),
  "settings-alerts": withText(
    { title: tk("help_settings_alerts_title"), body: tk("help_settings_alerts_body") },
    {},
  ),
  "settings-feeds": withText(
    { title: tk("help_settings_feeds_title"), body: tk("help_settings_feeds_body") },
    {},
  ),
  "settings-reporting": withText(
    { title: tk("help_settings_reporting_title"), body: tk("help_settings_reporting_body") },
    {},
  ),
  "settings-vpn": withText(
    { title: tk("help_settings_vpn_title"), body: tk("help_settings_vpn_body") },
    {},
  ),
  setup: withText(
    { title: tk("help_setup_title"), body: tk("help_setup_body") },
    {},
  ),
  "settings-ports": withText(
    { title: tk("help_settings_ports_title"), body: tk("help_settings_ports_body") },
    {},
  ),
  network: withText(
    { title: tk("help_network_title"), body: tk("help_network_body") },
    {},
  ),
  "network-members": withText(
    { title: tk("help_network_members_title"), body: tk("help_network_members_body") },
    {},
  ),
  "settings-network": withText(
    { title: tk("help_settings_network_title"), body: tk("help_settings_network_body") },
    {},
  ),
  styleguide: withText(
    { title: tk("help_styleguide_title"), body: tk("help_styleguide_body") },
    {},
  ),
} as const satisfies Record<string, HelpText>

export type HelpId = keyof typeof HELP

export const HELP_IDS = Object.keys(HELP) as HelpId[]

/** The help id of a Settings tab; unknown tabs fall back to General. */
export function settingsHelpId(tab: string): HelpId {
  const id = `settings-${tab}`
  return id in HELP ? (id as HelpId) : "settings-general"
}
