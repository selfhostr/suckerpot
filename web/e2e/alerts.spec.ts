import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M18: alerts and weekly reports, in the Settings Alerts tab. Mock data only (src/mocks/alerts.ts).

const ALERTS = "/settings?tab=alert-rules"

test("alerts and reports", async ({ page }, info) => {
  // The old address leads to the Settings tab.
  await page.goto("/defend/alerts")
  await expect(page).toHaveURL(/\/settings\?tab=alert-rules$/)
  await expect(h1(page, "Settings")).toBeVisible()
  if (info.project.name.startsWith("mobile")) {
    // A phone has a select, not a list of tabs.
    await expect(page.getByRole("combobox", { name: "Settings sections" })).toHaveText("Alerts")
  } else {
    await expect(page.getByRole("tab", { name: "Alerts", exact: true })).toHaveAttribute(
      "aria-selected",
      "true",
    )
  }
  await expect(page.getByRole("list", { name: "Alert rules" })).toBeVisible()
  await expect(page.getByRole("list", { name: "Recent alerts" })).toBeVisible()
  await expect(page.getByRole("list", { name: "Weekly reports" })).toBeVisible()
  await settle(page)
  await shoot(page, "alerts", info.project.name, true)
})

test("alerts: switch a rule on", async ({ page }, info) => {
  await page.goto(ALERTS)
  const rules = page.getByRole("list", { name: "Alert rules" })
  await expect(rules).toBeVisible()
  const row = rules.getByRole("listitem").filter({ hasText: "A new malware download host" })
  await row.getByRole("switch").click()
  await expect(row.getByRole("group", { name: "Send to" })).toBeVisible()
  await settle(page)
  await row.scrollIntoViewIfNeeded()
  await shoot(page, "alerts-rule-on", info.project.name)
})

test("weekly report", async ({ page }, info) => {
  await page.goto(ALERTS)
  await page.getByRole("list", { name: "Weekly reports" }).getByRole("link").first().click()
  await expect(page).toHaveURL(/\/reports\/\d{4}-\d{2}-\d{2}$/)
  await expect(page.getByRole("heading", { level: 1, name: /^Week of/ })).toBeVisible()
  await expect(page.getByText("What to do next")).toBeVisible()
  await expect(page.getByRole("link", { name: /Print or save as PDF/ })).toBeVisible()
  await settle(page)
  await shoot(page, "report", info.project.name, true)
  await page.getByRole("link", { name: "Alerts and reports" }).click()
  await expect(page).toHaveURL(/\/settings\?tab=alert-rules$/)
})

test("settings alert channels", async ({ page }, info) => {
  await page.goto("/settings?tab=alerts")
  const list = page.getByRole("list", { name: "Alert channels" })
  await expect(list).toBeVisible()
  await settle(page)
  await shoot(page, "settings-alerts", info.project.name)

  const row = list.getByRole("listitem").filter({ hasText: "SecOps channel" })
  await row.getByRole("button", { name: "Send test" }).click()
  await expect(row.getByText("Test requested.")).toBeVisible()
  await expect(row.getByText("The last test message arrived.")).toBeVisible()
  await settle(page)
  await shoot(page, "settings-alerts-tested", info.project.name)

  await page.getByRole("button", { name: /Add channel/ }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog).toBeVisible()
  await dialog.getByLabel("Name").fill("Teams ops")
  await dialog.getByRole("radio", { name: "Teams" }).click()
  await dialog.getByLabel("Webhook URL").fill("http://example.test/hook")
  await dialog.getByLabel("Your password").fill("a-demo-password")
  await dialog.getByRole("button", { name: "Add channel" }).click()
  await expect(dialog.getByText("The webhook URL must use https.")).toBeVisible()
  await shoot(page, "settings-alert-dialog", info.project.name)
})
