import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M24: the guided tour, the "?" page help, the setup checklist and the VPN controls.
// Mock data only (src/mocks/setup.ts, src/mocks/vpn.ts).

const STEPS = 7

test.describe("guided tour", () => {
  // A first visit: nothing in localStorage, so the tour opens by itself.
  test.use({ storageState: { cookies: [], origins: [] } })

  test("opens on the first visit, walks the seven steps, and does not come back", async ({
    page,
  }, info) => {
    await page.goto("/")
    const dialog = page.getByRole("dialog")
    await expect(dialog).toBeVisible()
    for (let i = 1; i <= STEPS; i++) {
      await expect(dialog.getByText(`Step ${i} of ${STEPS}`)).toBeVisible()
      if (i === STEPS) {
        await expect(dialog.getByRole("list", { name: "Setup checklist" })).toBeVisible()
        await expect(dialog.getByText(/just egress-check/)).toBeVisible()
      }
      await page.waitForLoadState("networkidle")
      await shoot(page, `tour-step-${i}`, info.project.name)
      if (i < STEPS) await dialog.getByRole("button", { name: "Next" }).click()
    }
    await dialog.getByRole("button", { name: "Done" }).click()
    await expect(dialog).toBeHidden()
    await page.reload()
    await settle(page)
    await expect(page.getByRole("dialog")).toHaveCount(0)
  })

  test("Escape closes it and Settings plays it again", async ({ page }) => {
    await page.goto("/")
    await expect(page.getByRole("dialog")).toBeVisible()
    await page.keyboard.press("Escape")
    await expect(page.getByRole("dialog")).toBeHidden()
    await page.goto("/settings")
    await expect(h1(page, "Settings")).toBeVisible()
    await page.getByRole("button", { name: "Take the tour" }).click()
    await expect(page.getByRole("dialog").getByText(`Step 1 of ${STEPS}`)).toBeVisible()
  })
})

test("page help popover", async ({ page }, info) => {
  await page.goto("/attacks")
  await expect(h1(page, "Attacks")).toBeVisible()
  await page.getByRole("button", { name: "About this page: Attacks" }).click()
  await expect(page.getByText(/Every connection to a sensor is a session/)).toBeVisible()
  await settle(page)
  await shoot(page, "page-help", info.project.name)
  await page.keyboard.press("Escape")

  // Settings has one text per tab.
  await page.goto("/settings?tab=vpn")
  await page.getByRole("button", { name: "About this page: VPN" }).click()
  await expect(page.getByText(/Only the vpn service has a route to the internet/)).toBeVisible()
})

test("setup checklist in Settings", async ({ page }, info) => {
  await page.goto("/settings")
  const list = page.getByRole("list", { name: "Setup checklist" })
  await expect(list).toBeVisible()
  await expect(list.getByRole("listitem")).toHaveCount(9)
  await expect(list.getByText("Needs attention")).toBeVisible()
  await expect(
    page.getByText(/The host firewall can't be seen from inside the stack/),
  ).toBeVisible()
  await settle(page)
  await shoot(page, "setup-checklist", info.project.name, true)
})

test("vpn closed gate: check now and reconnect in the status card", async ({ page }, info) => {
  await page.goto("/settings?tab=vpn&vpn=upload")
  await expect(page.getByText(/The gate is closed/).first()).toBeVisible()
  await expect(page.getByRole("button", { name: "Check now" })).toHaveCount(1)
  await expect(page.getByRole("button", { name: "Reconnect" })).toHaveCount(1)
  await settle(page)
  await shoot(page, "vpn-closed", info.project.name, true)

  await page.getByRole("button", { name: "Check now" }).click()
  await expect(page.getByRole("button", { name: "Checking…" })).toBeVisible()
  await shoot(page, "vpn-checking", info.project.name)
  // The mock answers after about four seconds; the tab looks every three.
  await expect(page.getByRole("button", { name: "Checking…" })).toHaveCount(0, { timeout: 15_000 })

  await page.getByRole("button", { name: "Reconnect" }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog.getByText(/Events are still recorded/)).toBeVisible()
  await settle(page)
  await shoot(page, "vpn-reconnect-dialog", info.project.name)
})
