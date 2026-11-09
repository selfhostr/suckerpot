import { expect, test } from "@playwright/test"
import { settle, shoot } from "./helpers"

// Pipeline banner and Settings card. Mock data only (src/mocks/pipeline.ts): `?pipeline=stalled`,
// `?pipeline=parked` and `?pipeline=unknown` pick the state; the default is `ok` (no banner).

test("pipeline stalled, overview", async ({ page }, info) => {
  await page.goto("/?pipeline=stalled")
  await expect(page.getByRole("alert")).toHaveText("Events are not being stored.")
  await expect(page.getByTestId("pipeline-stalled")).toContainText("have not been stored")
  await settle(page)
  await shoot(page, "pipeline-stalled-overview", info.project.name)
})

test("pipeline stalled, settings", async ({ page }, info) => {
  await page.goto("/settings?pipeline=stalled")
  await expect(page.getByTestId("pipeline-stalled")).toContainText("have not been stored")
  await expect(page.getByText("Pipeline", { exact: true }).first()).toBeVisible()
  await settle(page)
  await shoot(page, "pipeline-stalled-settings", info.project.name, true)
})

test("pipeline parked, overview, dismissed", async ({ page }, info) => {
  await page.goto("/?pipeline=parked")
  const notice = page.getByRole("status").filter({ hasText: "set aside" })
  await expect(notice).toBeVisible()
  await settle(page)
  await shoot(page, "pipeline-parked-overview", info.project.name)
  await notice.getByRole("button", { name: "Dismiss this notice" }).click()
  await expect(page.getByRole("status").filter({ hasText: "set aside" })).toHaveCount(0)
})

test("pipeline ok, settings", async ({ page }, info) => {
  await page.goto("/settings")
  await expect(page.getByText("Events are being stored normally.")).toBeVisible()
  await expect(page.getByTestId("pipeline-stalled")).toHaveCount(0)
  await settle(page)
  await shoot(page, "pipeline-ok-settings", info.project.name, true)
})
