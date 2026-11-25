import { expect, test } from "@playwright/test"
import { h1, settle, shoot, shootTall } from "./helpers"

// M15: campaigns, the techniques table and the "Part of campaign" chip, on mock data.

test("campaigns list", async ({ page }, info) => {
  await page.goto("/campaigns")
  await expect(h1(page, "Campaigns")).toBeVisible()
  await expect(page.getByRole("list", { name: "Campaigns" })).toBeVisible()
  await settle(page)
  await shootTall(page, "campaigns", info.project.name)

  // Filters live in the URL: quiet campaigns only, over all time.
  await page.goto("/campaigns?status=quiet&window=all")
  await expect(page.getByRole("list", { name: "Campaigns" })).toBeVisible()
  await expect(page.getByText("Password-list guessing over SSH #10")).toBeVisible()
  await settle(page)
  await shoot(page, "campaigns-quiet", info.project.name)

  await page.goto("/campaigns?technique=T1496")
  await expect(page.getByRole("list", { name: "Campaigns" })).toBeVisible()
  await settle(page)
  await shoot(page, "campaigns-technique", info.project.name)
})

test("campaign detail tells the attack in stages", async ({ page }, info) => {
  await page.goto("/campaigns")
  await expect(page.getByRole("list", { name: "Campaigns" })).toBeVisible()
  await page
    .getByRole("link", { name: /^Mirai-style loader over Telnet/ })
    .first()
    .click()
  await expect(h1(page, "Mirai-style loader over Telnet #3")).toBeVisible()
  // The playbook at a glance: six slots, each said as seen or not seen.
  const stages = page.getByRole("list", { name: /^Stages: / })
  await expect(stages).toBeVisible()
  await expect(stages.getByRole("listitem")).toHaveCount(6)
  await expect(page.getByRole("list", { name: "Lines from a real session" })).toBeVisible()
  await settle(page)
  await shoot(page, "campaign-detail", info.project.name, true)

  // From the campaign to one of its sessions: the session says which campaign it is part of.
  await page.getByRole("link", { name: /Open the full session/ }).click()
  await expect(page.getByRole("list", { name: "Events" })).toBeVisible()
  const chip = page.getByRole("link", { name: /Part of campaign/ })
  await expect(chip).toBeVisible()
  await settle(page)
  await shoot(page, "session-campaign-chip", info.project.name)
  await chip.click()
  await expect(h1(page, "Mirai-style loader over Telnet #3")).toBeVisible()
})

test("campaign whose sessions aged out keeps its counters", async ({ page }, info) => {
  await page.goto("/campaigns/10")
  await expect(h1(page, "Password-list guessing over SSH #10")).toBeVisible()
  await expect(page.getByText("The raw sessions have aged out")).toBeVisible()
  await settle(page)
  await shoot(page, "campaign-detail-quiet", info.project.name, true)

  await page.goto("/campaigns/999")
  await expect(page.getByRole("heading", { name: "Campaign not found" })).toBeVisible()
})

test("techniques table", async ({ page }, info) => {
  await page.goto("/techniques")
  await expect(h1(page, "Techniques")).toBeVisible()
  await expect(page.getByRole("list", { name: /Techniques, most sessions first/ })).toBeVisible()
  await settle(page)
  await shootTall(page, "techniques", info.project.name)

  await page.goto("/techniques?sensor=ssh&window=7")
  await expect(page.getByText("Last 7 days").first()).toBeVisible()
  await settle(page)
  await shoot(page, "techniques-ssh-7d", info.project.name)

  // A row opens the sessions that used the technique.
  await page
    .getByRole("link", { name: /Brute Force/ })
    .first()
    .click()
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  await expect(page).toHaveURL(/technique=T1110/)
})
