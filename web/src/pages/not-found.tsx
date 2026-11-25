import { Compass } from "lucide-react"
import { Link, isRouteErrorResponse, useRouteError } from "react-router"
import { EmptyState } from "@/components/empty-state"
import { Button } from "@/components/ui/button"

export function NotFoundPage() {
  return (
    <EmptyState
      icon={Compass}
      title="Page not found"
      description="This address does not match any page. The link may be old or mistyped."
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/">Go to Today</Link>
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
      : "Unknown error"
  return (
    <div className="mx-auto max-w-lg p-6">
      <EmptyState
        icon={Compass}
        title="Something went wrong"
        description={message}
        action={
          <Button asChild variant="outline" size="sm">
            <a href={import.meta.env.BASE_URL}>Reload</a>
          </Button>
        }
        className="mt-16 py-16"
      />
    </div>
  )
}
