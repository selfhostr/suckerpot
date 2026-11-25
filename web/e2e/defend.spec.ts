import { expect, test } from "@playwright/test"
import { h1, settle, shoot, shootTall } from "./helpers"

// M16 Defend. Mock data only: every address is from a documentation range, every host is example.*.

test("blocklists", async ({ page }, info) => {
  await page.goto("/defend/blocklists")
  await expect(h1(page, "Blocklists")).toBeVisible()
  await expect(page.getByRole("list", { name: "Blocklist entries" })).toBeVisible()
  await expect(page.getByText(/ready for your firewall/).first()).toBeVisible()
  await settle(page)
  await shootTall(page, "defend-blocklists", info.project.name)
  await page.evaluate(() => window.scrollTo(0, 0))
  await shoot(page, "defend-blocklists-top", info.project.name)
  await page.getByRole("button", { name: "Export and your own rules" }).click()
  await page.locator("#export").scrollIntoViewIfNeeded()
  await page.locator("#export").screenshot({
    path: `screenshots/defend-blocklists-export-${info.project.name}.png`,
  })

  // Filters live in the URL: one kind, high scores only.
  await page.goto("/defend/blocklists?kind=ip&min_score=70")
  await expect(page.getByRole("list", { name: "Blocklist entries" })).toBeVisible()
  await expect(page.getByRole("button", { name: /^IP addresses/ }).first()).toHaveAttribute(
    "aria-pressed",
    "true",
  )
  await settle(page)
  await shootTall(page, "defend-blocklists-ip-high", info.project.name)

  // An override from the row menu.
  await page
    .getByRole("button", { name: /^Actions for/ })
    .first()
    .click()
  await page.getByRole("menuitem", { name: "Always allow…" }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog).toBeVisible()
  await dialog.getByLabel("Note (optional)").fill("Our own scanner")
  // Changing the lists may ask for the dashboard password again.
  const password = dialog.getByLabel("Your password")
  if ((await password.count()) > 0) await password.fill("a-demo-password")
  await shoot(page, "defend-override-dialog", info.project.name)
  await dialog.getByRole("button", { name: "Always allow" }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByText("Always allowed").first()).toBeVisible()
})

test("detections", async ({ page }, info) => {
  await page.goto("/defend/detections")
  await expect(h1(page, "Detections")).toBeVisible()
  await expect(page.getByRole("heading", { name: "Review before deploying" })).toBeVisible()
  await expect(page.getByRole("list", { name: "Sigma rules" })).toBeVisible()
  await expect(page.getByText("Check this at your company")).toBeVisible()
  await settle(page)
  await page.getByRole("button", { name: /Web request probing PHP upload progress/ }).click()
  await expect(page.getByRole("figure").first()).toBeVisible()
  await shoot(page, "defend-detections", info.project.name, true)

  await page.goto("/defend/detections?kind=suricata")
  await expect(page.getByRole("list", { name: "Suricata rules" })).toBeVisible()
  await settle(page)
  await shoot(page, "defend-detections-suricata", info.project.name, true)
})

test("exposure", async ({ page }, info) => {
  await page.goto("/defend/exposure")
  await expect(h1(page, "Your exposure")).toBeVisible()
  await expect(page.getByRole("list", { name: "Your services" })).toBeVisible()
  await expect(page.getByText("Attacked but not in your list")).toBeVisible()
  await settle(page)
  await shoot(page, "defend-exposure", info.project.name, true)

  await page.getByRole("button", { name: /^Add MySQL to my list/ }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog).toBeVisible()
  await dialog.getByLabel("Name").fill("Orders database")
  await shoot(page, "defend-inventory-dialog", info.project.name)
  await dialog.getByRole("button", { name: "Add service" }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByRole("heading", { name: "Orders database" })).toBeVisible()
})

test("settings feeds", async ({ page }, info) => {
  await page.goto("/settings?tab=feeds")
  await expect(h1(page, "Settings")).toBeVisible()
  const tokens = page.getByRole("list", { name: "Feed tokens" })
  await expect(tokens).toBeVisible()
  await settle(page)
  await shoot(page, "defend-feeds", info.project.name, true)

  await page.getByRole("button", { name: "Create token" }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog).toBeVisible()
  await dialog.getByLabel("Name").fill("Branch firewall")
  await dialog.getByLabel("Your password").fill("wrong")
  await dialog.getByRole("button", { name: "Create token" }).click()
  await expect(dialog.getByText("That password is not correct.")).toBeVisible()
  await shoot(page, "defend-feeds-create", info.project.name)

  await dialog.getByLabel("Your password").fill("a-demo-password")
  await dialog.getByRole("button", { name: "Create token" }).click()
  await expect(dialog).toBeHidden()
  const reveal = page.getByRole("region", { name: /Copy your token now/ })
  await expect(reveal).toBeVisible()
  await expect(reveal.getByText(/cannot be shown again/)).toBeVisible()
  await settle(page)
  await shoot(page, "defend-feeds-token", info.project.name, true)
})

test("settings feeds off", async ({ page }, info) => {
  // Mock-only switch: the feeds endpoint answers as if FEEDS_ENABLED were false (the default).
  await page.addInitScript(() => {
    try {
      window.localStorage.setItem("suckerpot-mock-feeds", "off")
    } catch {
      // Storage blocked: the shot below then fails on its assertion, which is what we want.
    }
  })
  await page.goto("/settings?tab=feeds")
  await expect(h1(page, "Settings")).toBeVisible()
  await expect(page.getByText(/FEEDS_ENABLED=true/)).toBeVisible()
  await expect(page.getByRole("button", { name: "Create token" })).toBeDisabled()
  // The sections are a list beside the page on a computer, a select on a phone.
  await expect(
    page
      .getByRole("tab", { name: "Feeds" })
      .or(page.getByRole("combobox", { name: "Settings sections" })),
  ).toBeInViewport()
  await settle(page)
  await shoot(page, "defend-feeds-off", info.project.name, true)
})
