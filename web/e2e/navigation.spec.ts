import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// The shell: three sections that open onto their pages, the foot (Settings, Docs, GitHub, the
// account), the fold to an icon rail on desktop and the drawer on phones.

test("sidebar sections, pages and breadcrumb", async ({ page }, info) => {
  const mobile = info.project.name.startsWith("mobile")
  await page.goto("/defend/blocklists")
  await settle(page)
  // No hub tab strip any more: the pages are listed in the sidebar.
  await expect(page.getByRole("navigation", { name: /pages$/ })).toHaveCount(0)
  if (mobile) {
    await page.getByRole("button", { name: "Open navigation" }).click()
    await expect(page.getByRole("dialog")).toBeVisible()
  } else {
    const crumbs = page.getByRole("navigation", { name: "Breadcrumb" })
    await expect(crumbs.getByRole("listitem")).toHaveText(["Defend", "Blocklists"])
  }
  const nav = page.getByRole("navigation", { name: "Main" }).locator("visible=true")
  for (const section of ["Observe", "Understand", "Defend"]) {
    await expect(nav.getByRole("group", { name: section })).toBeVisible()
  }
  for (const label of ["Sessions", "Attackers", "Campaigns", "Scripts", "Trends", "CVE watch"]) {
    await expect(nav.getByRole("link", { name: label, exact: true })).toBeVisible()
  }
  await expect(nav.getByRole("link", { name: "Blocklists" })).toHaveAttribute(
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

  await nav.getByRole("link", { name: "Attacker networks" }).click()
  await expect(page).toHaveURL(/\/networks$/)
  await expect(page.getByRole("list", { name: "Attacker networks" })).toBeVisible()
  // The drawer closes once a page is picked.
  if (mobile) await expect(page.getByRole("dialog")).toHaveCount(0)

  // A folded section keeps its current page in view through the section itself.
  if (mobile) await page.getByRole("button", { name: "Open navigation" }).click()
  const observe = page.getByRole("button", { name: "Observe" }).locator("visible=true")
  await observe.click()
  await expect(observe).toHaveAttribute("aria-expanded", "false")
  await expect(page.getByRole("link", { name: "Sessions", exact: true })).toHaveCount(0)
  await observe.click()
  await expect(observe).toHaveAttribute("aria-expanded", "true")
  if (mobile) await page.keyboard.press("Escape")

  // The old address keeps working.
  await page.goto("/attackers?view=asns")
  await expect(page).toHaveURL(/\/networks$/)
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

  // Each section icon opens its pages beside the rail.
  await page.getByRole("button", { name: "Observe" }).click()
  const menu = page.getByRole("menu")
  await expect(menu.getByRole("menuitem", { name: "Attackers" })).toHaveAttribute(
    "aria-current",
    "page",
  )
  await shoot(page, "nav-rail-flyout", info.project.name)
  await menu.getByRole("menuitem", { name: "Sessions" }).click()
  await expect(page).toHaveURL(/\/attacks$/)
  await settle(page)
  await shoot(page, "nav-rail", info.project.name)

  // Ctrl B unfolds it again.
  await page.keyboard.press("Control+b")
  await expect(page.getByRole("button", { name: "Collapse sidebar" })).toBeVisible()
})

test("account menu: theme, masking, version", async ({ page }, info) => {
  await page.goto("/")
  await settle(page)
  if (info.project.name.startsWith("mobile"))
    await page.getByRole("button", { name: "Open navigation" }).click()
  await page
    .getByRole("button", { name: /^Account menu for / })
    .locator("visible=true")
    .click()
  const menu = page.getByRole("menu")
  await expect(menu.getByRole("menuitem", { name: "Sign out" })).toBeVisible()
  await expect(menu.getByRole("menuitemcheckbox", { name: /Mask IP addresses/ })).toBeVisible()
  await expect(menu.getByText("Mock data: nothing here is real traffic.")).toBeVisible()
  await shoot(page, "account-menu", info.project.name)
  await menu.getByRole("menuitem", { name: /Theme/ }).click()
  await page.getByRole("menuitemradio", { name: "Light" }).click()
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
