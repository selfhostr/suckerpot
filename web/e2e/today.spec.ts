import { expect, test, type Page } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M19: the Today home page (with the live map), the search palette, glossary terms and the
// research-scanner switch.

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
  await expect(page.getByRole("group", { name: "Visits per hour, last 24 hours" })).toBeVisible()
  await expect(page.locator("[data-todo]").first()).toBeVisible()
  await settle(page)
}

test("today", async ({ page }, info) => {
  await page.addInitScript(() => {
    ;(window as unknown as { __SUCKERPOT_MAP__: { freeze: boolean } }).__SUCKERPOT_MAP__ = {
      freeze: true,
    }
  })
  await freezeMotion(page)
  await openToday(page)

  // The day's sentence, the live map with its ticker and rankings, five numbers, the hours and at
  // most three things to do.
  await expect(page.getByText(/knocked on your decoy doors/)).toBeVisible()
  await expect(page.getByRole("list", { name: "Top addresses" })).toBeVisible()
  const day = page.getByRole("region", { name: "Last 24 hours" })
  for (const label of ["Visits", "Machines", "Countries", "Got in", "Tried to install"])
    await expect(day.getByText(label, { exact: true })).toBeVisible()
  expect(await page.locator("[data-todo]").count()).toBeLessThanOrEqual(3)

  // On a desktop screen everything fits: the page does not scroll.
  if (info.project.name.startsWith("desktop")) {
    const scroll = await page.evaluate(
      () => document.documentElement.scrollHeight - document.documentElement.clientHeight,
    )
    expect(scroll, "Today scrolls on desktop").toBeLessThanOrEqual(0)
  }
  await shoot(page, "today", info.project.name, true)

  // Every hour opens its visits.
  await page
    .getByRole("group", { name: "Visits per hour, last 24 hours" })
    .getByRole("link")
    .last()
    .click()
  await expect(page).toHaveURL(/\/attacks\?since=.+&until=/)
})

test("live opens today", async ({ page }) => {
  await freezeMotion(page)
  await page.goto("/live?sensor=ssh")
  await expect(h1(page, "Today")).toBeVisible()
  await expect(page).toHaveURL(/\/\?sensor=ssh$/)
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
  await page.goto("/networks")
  await expect(h1(page, "Attacker networks")).toBeVisible()
  await settle(page)
  const term = page.locator('[data-term="asn"]').first()
  await term.focus()
  await page.keyboard.press("Enter")
  await expect(page.getByText(/Autonomous System Number: the ID of the network/)).toBeVisible()
  await shoot(page, "term-open", info.project.name)
  await page.keyboard.press("Escape")
  await expect(page.getByText(/Autonomous System Number: the ID of the network/)).toHaveCount(0)
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
