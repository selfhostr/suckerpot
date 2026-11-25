import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// The shell: three sections, one row per entry, a switch between the pages of an entry, the foot
// (Settings, Docs and GitHub on one row, the account), the fold to an icon rail on desktop and the
// drawer on phones, and the version at the foot of every page.

test("sidebar entries, page switch and breadcrumb", async ({ page }, info) => {
  const mobile = info.project.name.startsWith("mobile")
  await page.goto("/defend/detections")
  await settle(page)
  // Blocklists and Detections are one entry, Block: a switch at the top of the page.
  const pages = page.getByRole("navigation", { name: "Block pages" })
  await expect(pages.getByRole("link")).toHaveText(["Lists", "Rules"])
  await expect(pages.getByRole("link", { name: "Rules" })).toHaveAttribute(
    "aria-current",
    "page",
  )
  // It never scrolls sideways.
  const overflow = await pages.getByRole("list").evaluate((el) => el.scrollWidth - el.clientWidth)
  expect(overflow).toBeLessThanOrEqual(0)
  if (mobile) {
    await page.getByRole("button", { name: "Open navigation" }).click()
    await expect(page.getByRole("dialog")).toBeVisible()
  } else {
    const crumbs = page.getByRole("navigation", { name: "Breadcrumb" })
    await expect(crumbs.getByRole("listitem")).toHaveText(["Defend", "Block", "Detections"])
  }
  const nav = page.getByRole("navigation", { name: "Main" }).locator("visible=true")
  for (const section of ["Observe", "Understand", "Defend"]) {
    await expect(nav.getByRole("group", { name: section })).toBeVisible()
  }
  await expect(nav.getByRole("group", { name: "Understand" }).getByRole("link")).toHaveText([
    "Campaigns",
    "Payloads",
    "Patterns",
  ])
  await expect(nav.getByRole("group", { name: "Defend" }).getByRole("link")).toHaveText([
    "Block",
    "Exposure",
    "Reports",
    "Network",
  ])
  for (const gone of ["Live", "Overview", "Alerts"])
    await expect(nav.getByRole("link", { name: gone, exact: true })).toHaveCount(0)
  // The entry stays current on all of its pages.
  await expect(nav.getByRole("link", { name: "Block" })).toHaveAttribute(
    "aria-current",
    "page",
  )
  await expect(
    page
      .getByRole("link", { name: /Documentation/ })
      .locator("visible=true")
      .first(),
  ).toHaveAttribute("href", "https://suckerpot.selfhostr.io/docs/")
  await expect(
    page
      .getByRole("link", { name: /GitHub/ })
      .locator("visible=true")
      .first(),
  ).toHaveAttribute("href", "https://github.com/selfhostr/suckerpot")
  await shoot(page, "nav-sections", info.project.name)

  await nav.getByRole("link", { name: "Attacks", exact: true }).click()
  await expect(page).toHaveURL(/\/attacks$/)
  // The drawer closes once a page is picked.
  if (mobile) await expect(page.getByRole("dialog")).toHaveCount(0)
  await page
    .getByRole("navigation", { name: "Attacks pages" })
    .getByRole("link", { name: "Networks" })
    .click()
  await expect(page).toHaveURL(/\/networks$/)
  await expect(page.getByRole("list", { name: "Attacker networks" })).toBeVisible()
  await settle(page)
  await shoot(page, "nav-page-switch", info.project.name)

  // A folded section keeps its current entry in view through the section itself.
  if (mobile) await page.getByRole("button", { name: "Open navigation" }).click()
  const observe = page.getByRole("button", { name: "Observe" }).locator("visible=true")
  await observe.click()
  await expect(observe).toHaveAttribute("aria-expanded", "false")
  await expect(page.getByRole("link", { name: "Attacks", exact: true })).toHaveCount(0)
  await observe.click()
  await expect(observe).toHaveAttribute("aria-expanded", "true")
  if (mobile) await page.keyboard.press("Escape")

  // The old addresses keep working.
  await page.goto("/attackers?view=asns")
  await expect(page).toHaveURL(/\/networks$/)
  for (const old of ["/live", "/overview"]) {
    await page.goto(old)
    await expect(page).toHaveURL(/\/$/)
  }
})

test("pages fill the width, and more when the sidebar folds", async ({ page }, info) => {
  test.skip(info.project.name.startsWith("mobile"), "phones use the drawer")
  await page.setViewportSize({ width: 1920, height: 1000 })
  await page.goto("/attackers")
  await settle(page)
  const frame = page.locator("[data-page-width]")
  const main = page.locator("main#main")
  const unfolded = (await frame.boundingBox())?.width ?? 0
  expect(unfolded).toBeCloseTo((await main.boundingBox())?.width ?? 0, 0)
  await page.getByRole("button", { name: "Collapse sidebar" }).click()
  await expect.poll(async () => (await frame.boundingBox())?.width ?? 0).toBeGreaterThan(unfolded)
  await expect.poll(async () => (await frame.boundingBox())?.width ?? 0).toBeGreaterThan(1850)
})

test("sidebar folds to an icon rail and remembers it", async ({ page }, info) => {
  test.skip(info.project.name.startsWith("mobile"), "phones use the drawer")
  await page.goto("/attackers")
  await settle(page)
  const aside = page.locator("aside#sidebar")
  const wide = (await aside.boundingBox())?.width ?? 0
  expect(wide).toBeGreaterThan(200)
  await page.getByRole("button", { name: "Collapse sidebar" }).click()
  await expect(page.getByRole("button", { name: "Expand sidebar" })).toBeVisible()
  await expect.poll(async () => (await aside.boundingBox())?.width ?? 0).toBeLessThan(64)
  await expect(page.locator("aside#sidebar").getByRole("link", { name: "Settings" })).toBeVisible()
  await page.reload()
  await settle(page)
  await expect(page.getByRole("button", { name: "Expand sidebar" })).toBeVisible()

  // Each section icon opens its entries beside the rail.
  await page.getByRole("button", { name: "Observe" }).click()
  const menu = page.getByRole("menu")
  await expect(menu.getByRole("menuitem", { name: "Attacks" })).toHaveAttribute(
    "aria-current",
    "page",
  )
  await shoot(page, "nav-rail-flyout", info.project.name)
  await menu.getByRole("menuitem", { name: "Attacks" }).click()
  await expect(page).toHaveURL(/\/attacks$/)
  await settle(page)
  await shoot(page, "nav-rail", info.project.name)

  // Ctrl B unfolds it again.
  await page.keyboard.press("Control+b")
  await expect(page.getByRole("button", { name: "Collapse sidebar" })).toBeVisible()
})

test("account menu: theme, masking; the version at the foot", async ({ page }, info) => {
  await page.goto("/")
  await settle(page)
  // The version sits at the foot of the page, the mock-data note beside it.
  const foot = page.getByRole("contentinfo")
  await expect(foot.getByRole("link", { name: /SuckerPot v/ })).toHaveAttribute("href", "/settings")
  await expect(foot.getByText("Mock data: nothing here is real traffic.")).toBeVisible()
  if (info.project.name.startsWith("mobile"))
    await page.getByRole("button", { name: "Open navigation" }).click()
  const account = page.getByRole("button", { name: /^Account menu for / }).locator("visible=true")
  // Only the name under the avatar: no role.
  await expect(account).not.toContainText(/owner/i)
  await account.click()
  const menu = page.getByRole("menu")
  await expect(menu.getByRole("menuitem", { name: "Sign out" })).toBeVisible()
  await expect(menu.getByRole("menuitemcheckbox", { name: /Mask IP addresses/ })).toBeVisible()
  await expect(menu.getByText(/SuckerPot v|Last sign-in|\.env/)).toHaveCount(0)
  await shoot(page, "account-menu", info.project.name)
  // One item cycles the theme and stays open to show the change: light, dark, system.
  const theme = menu.getByRole("menuitem", { name: /^Theme/ })
  const before = await theme.textContent()
  await theme.click()
  await expect(menu).toBeVisible()
  await expect(theme).not.toHaveText(before ?? "")
  for (let i = 0; i < 2 && !(await theme.textContent())?.includes("Light"); i++) await theme.click()
  await expect(theme).toContainText("Light")
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light")
})

test("settings tabs", async ({ page }, info) => {
  await page.goto("/settings")
  await expect(h1(page, "Settings")).toBeVisible()
  // The tour and the styleguide (mock and development builds) are reached from here.
  await expect(page.getByRole("button", { name: "Take the tour" })).toBeVisible()
  await expect(page.getByRole("link", { name: "Styleguide" })).toHaveAttribute(
    "href",
    "/styleguide",
  )
  await expect(page.getByRole("tab")).toHaveText([
    "General",
    "Keys",
    "Users",
    "Audit",
    "Sensors & ports",
    "Alerts",
    "Alert channels",
    "Feeds",
    "Reporting",
    "VPN",
    "SuckerPot network",
  ])
  await page.getByRole("tab", { name: "Alert channels" }).click()
  await expect(page).toHaveURL(/tab=alerts/)
  await expect(page.getByRole("list", { name: "Alert channels" })).toBeVisible()
  await settle(page)
  await shoot(page, "settings-alert-channels", info.project.name)
})
