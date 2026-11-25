import { expect, test, type Page } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M19: the Today home page, the search palette, glossary terms and the research-scanner switch.

/** Entrance motion is frozen (reduced motion is already on; this also covers the fallback). */
async function freezeMotion(page: Page) {
  await page.addInitScript(() => {
    ;(window as unknown as { __SUCKERPOT_MOTION__: { freeze: boolean } }).__SUCKERPOT_MOTION__ = {
      freeze: true,
    }
  })
}

async function openToday(page: Page, path = "/") {
  await page.goto(path)
  await expect(h1(page, "Today")).toBeVisible()
  await expect(page.getByRole("region", { name: "Stories of the day" })).toBeVisible()
  await expect(page.locator("[data-card]").first()).toBeVisible()
  await settle(page)
}

test("today", async ({ page }, info) => {
  await freezeMotion(page)
  await openToday(page)

  // A headline, five numbers, the flow, the hour strip, 3 to 5 stories, then the to-do cards.
  await expect(page.getByText(/knocked on your decoy doors/)).toBeVisible()
  await expect(page.getByRole("slider", { name: /hour of the last day/i })).toBeVisible()
  const stories = page.locator("[data-story]")
  expect(await stories.count()).toBeGreaterThanOrEqual(3)
  expect(await stories.count()).toBeLessThanOrEqual(5)
  await expect(page.getByText(/left out\./)).toBeVisible()
  await shoot(page, "today", info.project.name, true)

  // Technical details are one click away.
  const first = stories.first()
  await first.getByRole("button", { name: "Technical details" }).click()
  await expect(first.getByText(/login_attempt/)).toBeVisible()
  await shoot(page, "today-story-technical", info.project.name)

  // Everything opens a filtered view.
  await first.getByRole("link", { name: "Open the full session" }).click()
  await expect(page).toHaveURL(/\/attacks\/demo-story-/)
})

test("today in the navigation", async ({ page }, info) => {
  await freezeMotion(page)
  await page.goto("/live")
  if (info.project.name.startsWith("mobile")) {
    await page.getByRole("button", { name: "Open navigation" }).click()
  }
  await page
    .getByRole("link", { name: "Today", exact: true })
    .locator("visible=true")
    .first()
    .click()
  await expect(h1(page, "Today")).toBeVisible()
  await expect(page).toHaveURL(/\/$/)
})

test("search palette", async ({ page }, info) => {
  await freezeMotion(page)
  await openToday(page)
  if (info.project.name.startsWith("desktop")) {
    await page.keyboard.press("Control+k")
  } else {
    await page.getByRole("button", { name: "Search" }).locator("visible=true").first().click()
  }
  const dialog = page.getByRole("dialog", { name: "Search" })
  await expect(dialog).toBeVisible()
  await shoot(page, "search-empty", info.project.name)

  await page.keyboard.type("mirai")
  await expect(dialog.getByText("Campaigns")).toBeVisible()
  await expect(
    dialog.getByRole("option", { name: /Mirai-style loader over Telnet #3/ }),
  ).toBeVisible()
  await shoot(page, "search-campaign", info.project.name)

  await page.keyboard.press("Control+a")
  await page.keyboard.type("192.0.2.")
  await expect(dialog.getByText("Addresses")).toBeVisible()
  await shoot(page, "search-ip-prefix", info.project.name)

  await page.keyboard.press("Control+a")
  await page.keyboard.type("zzzz-nothing")
  await expect(dialog.getByText(/Nothing matches/)).toBeVisible()

  await page.keyboard.press("Control+a")
  await page.keyboard.type("mirai")
  await expect(dialog.getByRole("option", { name: /Mirai-style loader/ })).toBeVisible()
  await page.keyboard.press("Enter")
  await expect(page).toHaveURL(/\/campaigns\/3/)
})

test("glossary term", async ({ page }, info) => {
  await freezeMotion(page)
  await openToday(page)
  const term = page.locator('dl [data-term="exploit"]').first()
  await term.scrollIntoViewIfNeeded()
  await term.focus()
  await page.keyboard.press("Enter")
  await expect(page.getByText(/A request or program built to abuse a specific flaw/)).toBeVisible()
  await shoot(page, "term-open", info.project.name)
  await page.keyboard.press("Escape")
  await expect(page.getByText(/A request or program built to abuse a specific flaw/)).toHaveCount(0)
})

test("hide research scanners", async ({ page }, info) => {
  await freezeMotion(page)
  await page.goto("/attacks?scanners=hide")
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  await settle(page)
  const badge = page.locator('[title^="Known research scanner"]')
  await expect(badge).toHaveCount(0)

  // The switch sits in the header (desktop) or the navigation drawer (phones); the count is its
  // description (a tooltip in the header, a line under it in the drawer).
  if (info.project.name.startsWith("mobile")) {
    await page.getByRole("button", { name: "Open navigation" }).click()
  }
  const toggle = page
    .getByRole("switch", { name: /Hide research scanners/ })
    .locator("visible=true")
  await expect(toggle).toBeChecked()
  await expect(toggle).toHaveAccessibleDescription(/sessions? hidden \(last 24 h\)/)
  await shoot(page, "scanner-toggle-on", info.project.name)

  await toggle.click()
  await expect(toggle).not.toBeChecked()
  await expect(toggle).toHaveAccessibleDescription(/from scanners \(last 24 h\)/)
  if (info.project.name.startsWith("mobile")) await page.keyboard.press("Escape")
  await expect(badge.locator("visible=true").first()).toBeVisible()
  await settle(page)
  await shoot(page, "attacks-with-scanners", info.project.name)
})
