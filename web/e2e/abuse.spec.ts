import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M22: abuse reports. Mock data only (src/mocks/abuse.ts).

test("abuse reports list", async ({ page }, info) => {
  await page.goto("/defend/abuse")
  await expect(h1(page, "Abuse reports")).toBeVisible()
  await expect(page.getByRole("heading", { name: "Example Hosting B.V." })).toBeVisible()
  await expect(page.getByText("No contact found")).toBeVisible()
  await settle(page)
  await shoot(page, "abuse", info.project.name, true)
})

test("abuse report draft", async ({ page }, info) => {
  await page.goto("/defend/abuse/7b1f3a52-9c0e-4d2a-8f61-1a2b3c4d5e01")
  await expect(page.getByLabel("Body", { exact: true })).toBeVisible()
  await expect(page.getByText("Nothing identifying found")).toBeVisible()
  await settle(page)
  await shoot(page, "abuse-report", info.project.name, true)
})

test("abuse report blocked and demo", async ({ page }, info) => {
  await page.goto("/defend/abuse/5e6f7a80-3b4c-4d5e-8f90-4d5e6f7a8b04")
  await expect(page.getByText("Blocked").first()).toBeVisible()
  await settle(page)
  await shoot(page, "abuse-report-blocked", info.project.name, true)
  await page.goto("/defend/abuse/a41e5b60-2d7c-4f18-8b93-3c4d5e6f7a03")
  await expect(page.getByText("Demo data, do not send.")).toBeVisible()
})

test("settings reporting", async ({ page }, info) => {
  await page.goto("/settings?tab=reporting")
  await expect(page.getByRole("textbox", { name: "Reply contact" })).toBeVisible()
  await expect(
    page.locator("#reporting-never").getByText("Never in a report", { exact: true }),
  ).toBeVisible()
  // The wording form has eight optional texts; the mailbox card has its own two (see results.spec.ts).
  const wording = page.locator("form", {
    has: page.getByRole("textbox", { name: "Reply contact" }),
  })
  await expect(wording.getByText("Optional", { exact: true })).toHaveCount(8)
  await settle(page)
  await shoot(page, "settings-reporting", info.project.name, true)
})

test("sample bundle", async ({ page }, info) => {
  await page.goto("/malware?view=samples")
  const list = page.getByRole("list", { name: "Samples" })
  await expect(list).toBeVisible()
  const add = list.getByRole("button", { name: "Add to sample bundle" }).locator("visible=true")
  await add.nth(0).click()
  await add.nth(0).click()
  await add.nth(0).click()
  await expect(page.getByText("3 samples in the bundle, room for 7 more.")).toBeVisible()
  await settle(page)
  await shoot(page, "sample-bundle", info.project.name)

  await page.getByRole("button", { name: "Download bundle" }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog.getByText("infected", { exact: true })).toBeVisible()
  await settle(page)
  await shoot(page, "sample-bundle-dialog", info.project.name)
  await dialog.getByLabel(/password/i).fill("demo-password")
  await dialog.getByRole("button", { name: "Download" }).click()
  await expect(dialog).toBeHidden()
})
