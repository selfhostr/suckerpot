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

/**
 * The "?" beside a card, a section or a column: what it shows, where the figures come from and what
 * to do with them. Titles reuse the card's own label, so the popover and the card say the same.
 */
export const CARD_HELP = {
  language: withText({ title: tk("account_language"), body: tk("help_card_language_body") }, {}),
  leaders: withText({ title: tk("help_card_leaders_title"), body: tk("help_card_leaders_body") }, {}),
  hourly: withText({ title: tk("charts_hourly_title"), body: tk("help_card_hourly_body") }, {}),
  todo: withText({ title: tk("today_todo_title"), body: tk("help_card_todo_body") }, {}),
  pipeline: withText({ title: tk("pipeline_title"), body: tk("help_card_pipeline_body") }, {}),
  sensors: withText({ title: tk("settings_sensors_title"), body: tk("help_card_sensors_body") }, {}),
  storage: withText({ title: tk("help_card_storage_title"), body: tk("help_card_storage_body") }, {}),
  egress: withText({ title: tk("egress_eyebrow"), body: tk("help_card_egress_body") }, {}),
  checklist: withText({ title: tk("checklist_title"), body: tk("help_card_checklist_body") }, {}),
  tags: withText({ title: tk("help_card_tags_title"), body: tk("help_card_tags_body") }, {}),
  new: withText({ title: tk("help_card_new_title"), body: tk("help_card_new_body") }, {}),
  indicators: withText({ title: tk("infra_indicators_title"), body: tk("help_card_indicators_body") }, {}),
  c2: withText({ title: tk("c2_list_label"), body: tk("help_card_c2_body") }, {}),
  overrides: withText({ title: tk("overrides_eyebrow"), body: tk("help_card_overrides_body") }, {}),
  company: withText({ title: tk("detections_company_title"), body: tk("help_card_company_body") }, {}),
  unlisted: withText({ title: tk("exposure_unlisted_title"), body: tk("help_card_unlisted_body") }, {}),
  node: withText({ title: tk("network_node_eyebrow"), body: tk("help_card_node_body") }, {}),
  targets: withText({ title: tk("network_targets_eyebrow"), body: tk("help_card_targets_body") }, {}),
  effect: withText({ title: tk("results_effect_eyebrow"), body: tk("help_card_effect_body") }, {}),
  queue: withText({ title: tk("send_queue_eyebrow"), body: tk("help_card_queue_body") }, {}),
  forms: withText({ title: tk("abuse_form_queue_eyebrow"), body: tk("help_card_forms_body") }, {}),
  blocked: withText({ title: tk("abuse_blocked_eyebrow"), body: tk("help_card_blocked_body") }, {}),
} as const satisfies Record<string, HelpText>

export type CardHelpId = keyof typeof CARD_HELP

export const CARD_HELP_IDS = Object.keys(CARD_HELP) as CardHelpId[]

export const HELP_IDS = Object.keys(HELP) as HelpId[]

/** The help id of a Settings tab; unknown tabs fall back to General. */
export function settingsHelpId(tab: string): HelpId {
  const id = `settings-${tab}`
  return id in HELP ? (id as HelpId) : "settings-general"
}
