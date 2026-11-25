/* eslint-disable react-refresh/only-export-components -- route table: lazy page components live next to the router on purpose. */
import { Suspense, lazy } from "react"
import { Navigate, createBrowserRouter, useLocation, type RouteObject } from "react-router"
import { PageSkeleton } from "@/components/skeletons"
import { NotFoundPage, RouteError } from "@/pages/not-found"
import { AppShell } from "./app-shell"
import { RequireAuth } from "./auth"
import { ALERTS_SETTINGS } from "./nav"
import type { RouteHandle } from "./page-width"
import { installViewTransitions } from "./view-transitions"

// Heavy pages (charts, terminal emulator, virtualised feeds) load on demand.
const TodayPage = lazy(() => import("@/pages/today").then((m) => ({ default: m.TodayPage })))
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
const AttacksPage = lazy(() => import("@/pages/attacks").then((m) => ({ default: m.AttacksPage })))
// Signed-out screens: not needed when a session already exists.
const LoginPage = lazy(() => import("@/pages/login").then((m) => ({ default: m.LoginPage })))
const SetPasswordPage = lazy(() =>
  import("@/pages/set-password").then((m) => ({ default: m.SetPasswordPage })),
)
const SetupPage = lazy(() => import("@/pages/setup").then((m) => ({ default: m.SetupPage })))
// The styleguide is for development and the mock builds only. Both flags are replaced by constants
// at build time, so a production build drops the dynamic import and the page never ships.
const SHOW_STYLEGUIDE = import.meta.env.DEV || import.meta.env.VITE_MOCK === "1"
const StyleguidePage = SHOW_STYLEGUIDE
  ? lazy(() => import("@/pages/styleguide").then((m) => ({ default: m.StyleguidePage })))
  : null

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
const ReportPage = lazy(() => import("@/pages/report").then((m) => ({ default: m.ReportPage })))

/** Suspense with a skeleton in the final layout, so nothing jumps when the chunk lands. */
function Lazy({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<PageSkeleton />}>{children}</Suspense>
}

export const router = createBrowserRouter(
  [
    {
      path: "login",
      element: (
        <Suspense fallback={null}>
          <LoginPage />
        </Suspense>
      ),
    },
    {
      path: "set-password",
      element: (
        <Suspense fallback={null}>
          <SetPasswordPage />
        </Suspense>
      ),
    },
    {
      element: <RequireAuth />,
      errorElement: <RouteError />,
      children: [appRoutes()],
    },
  ],
  // "/" in a normal build, "/demo/" in the hosted demo.
  { basename: import.meta.env.BASE_URL.replace(/\/$/, "") || undefined },
)

// Page changes animate with the View Transitions API (view-transitions.ts).
installViewTransitions(router)

/** Live and Overview became part of Today: keep the query string (a sensor filter) on the way. */
function ToToday() {
  const { search, hash } = useLocation()
  return <Navigate to={{ pathname: "/", search, hash }} replace />
}

/**
 * Every page fills the content column (page-width.ts); only the setup form declares
 * `handle.width: "prose"`, which keeps its own column at reading width.
 */
export function appRoutes(): RouteObject {
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
      // The live map and the day's figures are part of Today now: old links land there.
      { path: "live", element: <ToToday /> },
      { path: "overview", element: <ToToday /> },
      {
        path: "attacks",
        element: (
          <Lazy>
            <AttacksPage />
          </Lazy>
        ),
      },
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
        handle: { width: "prose" } satisfies RouteHandle,
        element: (
          <Lazy>
            <SetupPage />
          </Lazy>
        ),
      },
      ...(StyleguidePage
        ? [
            {
              path: "styleguide",
              element: (
                <Lazy>
                  <StyleguidePage />
                </Lazy>
              ),
            },
          ]
        : []),
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
      // The alert rules moved next to the channels in Settings.
      { path: "defend/alerts", element: <Navigate to={ALERTS_SETTINGS} replace /> },
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
