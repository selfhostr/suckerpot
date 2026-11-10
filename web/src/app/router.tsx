/* eslint-disable react-refresh/only-export-components -- route table: lazy page components live next to the router on purpose. */
import { Suspense, lazy } from "react"
import { createBrowserRouter, type RouteObject } from "react-router"
import { PageSkeleton } from "@/components/skeletons"
import { AttacksPage } from "@/pages/attacks"
import { NotFoundPage, RouteError } from "@/pages/not-found"
import { LoginPage } from "@/pages/login"
import { SetPasswordPage } from "@/pages/set-password"
import { AppShell } from "./app-shell"
import { RequireAuth } from "./auth"

// Heavy pages (charts, terminal emulator, virtualised feeds) load on demand.
const OverviewPage = lazy(() =>
  import("@/pages/overview").then((m) => ({ default: m.OverviewPage })),
)
const TodayPage = lazy(() => import("@/pages/today").then((m) => ({ default: m.TodayPage })))
const LivePage = lazy(() => import("@/pages/live").then((m) => ({ default: m.LivePage })))
const SessionDetailPage = lazy(() =>
  import("@/pages/session-detail").then((m) => ({ default: m.SessionDetailPage })),
)
const AttackersPage = lazy(() =>
  import("@/pages/attackers").then((m) => ({ default: m.AttackersPage })),
)
const NetworksPage = lazy(() =>
  import("@/pages/attackers").then((m) => ({ default: m.NetworksPage })),
)
const AttackerDetailPage = lazy(() =>
  import("@/pages/attacker-detail").then((m) => ({ default: m.AttackerDetailPage })),
)
const TrendsPage = lazy(() => import("@/pages/trends").then((m) => ({ default: m.TrendsPage })))
const CvesPage = lazy(() => import("@/pages/cves").then((m) => ({ default: m.CvesPage })))
const MalwarePage = lazy(() => import("@/pages/malware").then((m) => ({ default: m.MalwarePage })))
const InfrastructurePage = lazy(() =>
  import("@/pages/infrastructure").then((m) => ({ default: m.InfrastructurePage })),
)
const SettingsPage = lazy(() =>
  import("@/pages/settings").then((m) => ({ default: m.SettingsPage })),
)
const SetupPage = lazy(() => import("@/pages/setup").then((m) => ({ default: m.SetupPage })))
const StyleguidePage = lazy(() =>
  import("@/pages/styleguide").then((m) => ({ default: m.StyleguidePage })),
)

const CampaignsPage = lazy(() =>
  import("@/pages/campaigns").then((m) => ({ default: m.CampaignsPage })),
)
const CampaignDetailPage = lazy(() =>
  import("@/pages/campaign-detail").then((m) => ({ default: m.CampaignDetailPage })),
)
const TechniquesPage = lazy(() =>
  import("@/pages/techniques").then((m) => ({ default: m.TechniquesPage })),
)
const SampleDetailPage = lazy(() =>
  import("@/pages/sample-detail").then((m) => ({ default: m.SampleDetailPage })),
)
const ScriptsPage = lazy(() => import("@/pages/scripts").then((m) => ({ default: m.ScriptsPage })))
const ScriptDetailPage = lazy(() =>
  import("@/pages/script-detail").then((m) => ({ default: m.ScriptDetailPage })),
)
const BlocklistsPage = lazy(() =>
  import("@/pages/blocklists").then((m) => ({ default: m.BlocklistsPage })),
)
const DetectionsPage = lazy(() =>
  import("@/pages/detections").then((m) => ({ default: m.DetectionsPage })),
)
const ExposurePage = lazy(() =>
  import("@/pages/exposure").then((m) => ({ default: m.ExposurePage })),
)
const AbusePage = lazy(() => import("@/pages/abuse").then((m) => ({ default: m.AbusePage })))
const ResultsPage = lazy(() => import("@/pages/results").then((m) => ({ default: m.ResultsPage })))
const ResultsTargetPage = lazy(() =>
  import("@/pages/results-target").then((m) => ({ default: m.ResultsTargetPage })),
)
const AbuseDetailPage = lazy(() =>
  import("@/pages/abuse-detail").then((m) => ({ default: m.AbuseDetailPage })),
)
const NetworkPage = lazy(() => import("@/pages/network").then((m) => ({ default: m.NetworkPage })))
const NetworkMembersPage = lazy(() =>
  import("@/pages/network-members").then((m) => ({ default: m.NetworkMembersPage })),
)
const AlertsPage = lazy(() => import("@/pages/alerts").then((m) => ({ default: m.AlertsPage })))
const ReportPage = lazy(() => import("@/pages/report").then((m) => ({ default: m.ReportPage })))

/** Suspense with a skeleton in the final layout, so nothing jumps when the chunk lands. */
function Lazy({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<PageSkeleton />}>{children}</Suspense>
}

export const router = createBrowserRouter(
  [
    { path: "login", element: <LoginPage /> },
    { path: "set-password", element: <SetPasswordPage /> },
    {
      element: <RequireAuth />,
      errorElement: <RouteError />,
      children: [appRoutes()],
    },
  ],
  // "/" in a normal build, "/demo/" in the hosted demo.
  { basename: import.meta.env.BASE_URL.replace(/\/$/, "") || undefined },
)

function appRoutes(): RouteObject {
  return {
    element: <AppShell />,
    errorElement: <RouteError />,
    children: [
      {
        index: true,
        element: (
          <Lazy>
            <TodayPage />
          </Lazy>
        ),
      },
      {
        path: "live",
        element: (
          <Lazy>
            <LivePage />
          </Lazy>
        ),
      },
      {
        path: "overview",
        element: (
          <Lazy>
            <OverviewPage />
          </Lazy>
        ),
      },
      { path: "attacks", element: <AttacksPage /> },
      {
        path: "attacks/:sessionId",
        element: (
          <Lazy>
            <SessionDetailPage />
          </Lazy>
        ),
      },
      {
        path: "attackers",
        element: (
          <Lazy>
            <AttackersPage />
          </Lazy>
        ),
      },
      {
        path: "networks",
        element: (
          <Lazy>
            <NetworksPage />
          </Lazy>
        ),
      },
      {
        path: "attackers/:ip",
        element: (
          <Lazy>
            <AttackerDetailPage />
          </Lazy>
        ),
      },
      {
        path: "trends",
        element: (
          <Lazy>
            <TrendsPage />
          </Lazy>
        ),
      },
      {
        path: "malware",
        element: (
          <Lazy>
            <MalwarePage />
          </Lazy>
        ),
      },
      {
        path: "cves",
        element: (
          <Lazy>
            <CvesPage />
          </Lazy>
        ),
      },
      {
        path: "infrastructure",
        element: (
          <Lazy>
            <InfrastructurePage />
          </Lazy>
        ),
      },
      {
        path: "settings",
        element: (
          <Lazy>
            <SettingsPage />
          </Lazy>
        ),
      },
      {
        path: "setup",
        element: (
          <Lazy>
            <SetupPage />
          </Lazy>
        ),
      },
      {
        path: "styleguide",
        element: (
          <Lazy>
            <StyleguidePage />
          </Lazy>
        ),
      },
      {
        path: "campaigns",
        element: (
          <Lazy>
            <CampaignsPage />
          </Lazy>
        ),
      },
      {
        path: "campaigns/:id",
        element: (
          <Lazy>
            <CampaignDetailPage />
          </Lazy>
        ),
      },
      {
        path: "techniques",
        element: (
          <Lazy>
            <TechniquesPage />
          </Lazy>
        ),
      },
      {
        path: "malware/samples/:sha256",
        element: (
          <Lazy>
            <SampleDetailPage />
          </Lazy>
        ),
      },
      {
        path: "scripts",
        element: (
          <Lazy>
            <ScriptsPage />
          </Lazy>
        ),
      },
      {
        path: "scripts/:id",
        element: (
          <Lazy>
            <ScriptDetailPage />
          </Lazy>
        ),
      },
      {
        path: "defend/blocklists",
        element: (
          <Lazy>
            <BlocklistsPage />
          </Lazy>
        ),
      },
      {
        path: "defend/detections",
        element: (
          <Lazy>
            <DetectionsPage />
          </Lazy>
        ),
      },
      {
        path: "defend/exposure",
        element: (
          <Lazy>
            <ExposurePage />
          </Lazy>
        ),
      },
      {
        path: "defend/alerts",
        element: (
          <Lazy>
            <AlertsPage />
          </Lazy>
        ),
      },
      {
        path: "defend/abuse",
        element: (
          <Lazy>
            <AbusePage />
          </Lazy>
        ),
      },
      {
        path: "defend/abuse/:publicId",
        element: (
          <Lazy>
            <AbuseDetailPage />
          </Lazy>
        ),
      },
      {
        path: "defend/results",
        element: (
          <Lazy>
            <ResultsPage />
          </Lazy>
        ),
      },
      {
        path: "defend/results/targets/:id",
        element: (
          <Lazy>
            <ResultsTargetPage />
          </Lazy>
        ),
      },
      {
        path: "network",
        element: (
          <Lazy>
            <NetworkPage />
          </Lazy>
        ),
      },
      {
        path: "network/members",
        element: (
          <Lazy>
            <NetworkMembersPage />
          </Lazy>
        ),
      },
      {
        path: "reports/:week",
        element: (
          <Lazy>
            <ReportPage />
          </Lazy>
        ),
      },
      { path: "*", element: <NotFoundPage /> },
    ],
  }
}
