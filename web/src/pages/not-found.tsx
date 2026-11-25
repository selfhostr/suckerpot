import { Compass } from "lucide-react"
import { Link, isRouteErrorResponse, useRouteError } from "react-router"
import { EmptyState } from "@/components/empty-state"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"

export function NotFoundPage() {
  return (
    <EmptyState
      icon={Compass}
      title={t("notfound_title")}
      description={t("notfound_description")}
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/">{t("notfound_go_today")}</Link>
        </Button>
      }
      className="mt-10 py-16"
    />
  )
}

export function RouteError() {
  const error = useRouteError()
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : error instanceof Error
      ? error.message
      : t("notfound_unknown_error")
  return (
    <div className="mx-auto max-w-lg p-6">
      <EmptyState
        icon={Compass}
        title={t("notfound_error_title")}
        description={message}
        action={
          <Button asChild variant="outline" size="sm">
            <a href={import.meta.env.BASE_URL}>{t("notfound_reload")}</a>
          </Button>
        }
        className="mt-16 py-16"
      />
    </div>
  )
}
