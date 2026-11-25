import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M25: the To send queue and optional SMTP sending. Mock data only (src/mocks/abuse-send.ts).

test("abuse send queue", async ({ page }, info) => {
  await page.goto("/defend/abuse?status=queue")
  await expect(h1(page, "Abuse reports")).toBeVisible()
  await expect(page.getByText("Open your mailbox through your VPN")).toBeVisible()
  await expect(page.getByLabel("Message", { exact: true })).toBeVisible()
  await expect(page.getByLabel("Progress")).toHaveText("Report 1 of 4")
  await settle(page)
  await shoot(page, "abuse-send-queue", info.project.name, true)
})

test("abuse send queue skip and mark sent", async ({ page }) => {
  await page.goto("/defend/abuse?status=queue")
  await expect(page.getByLabel("Progress")).toHaveText("Report 1 of 4")
  await page.getByRole("button", { name: "Skip" }).click()
  await expect(page.getByLabel("Progress")).toHaveText("Report 1 of 4")
  await page.getByRole("button", { name: "Mark as sent, next" }).click()
  await expect(page.getByLabel("Progress")).toHaveText("Report 2 of 4")
})

test("abuse send now dialog", async ({ page }, info) => {
  await page.goto("/defend/abuse?status=queue")
  await page.getByRole("button", { name: "Send now" }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog.getByText("Send this report now?")).toBeVisible()
  await expect(dialog.getByText(/abuse@example\.org/)).toBeVisible()
  await settle(page)
  await shoot(page, "abuse-send-now", info.project.name)
})

test("settings sending off and automatic", async ({ page }, info) => {
  await page.goto("/settings?tab=reporting")
  const mode = page.getByRole("radiogroup", { name: "Sending mode" })
  await expect(mode).toBeVisible()
  await mode.getByRole("radio", { name: "Off" }).click()
  await expect(page.getByText(/Nothing is sent by SuckerPot/)).toBeVisible()
  await mode.scrollIntoViewIfNeeded()
  await settle(page)
  await shoot(page, "settings-sending-off", info.project.name)

  await mode.getByRole("radio", { name: "Automatic" }).click()
  await expect(page.getByText(/sent without you reading them/)).toBeVisible()
  await mode.scrollIntoViewIfNeeded()
  await settle(page)
  await shoot(page, "settings-sending-auto", info.project.name)
})

test("settings sending form actions", async ({ page }, info) => {
  await page.goto("/settings?tab=reporting")
  await expect(page.getByRole("button", { name: "Send a test" })).toBeVisible()
  await expect(page.getByText(/sent today/)).toBeVisible()
  await page.getByRole("button", { name: "Remove SMTP" }).scrollIntoViewIfNeeded()
  await settle(page)
  await shoot(page, "settings-sending-actions", info.project.name)
})
