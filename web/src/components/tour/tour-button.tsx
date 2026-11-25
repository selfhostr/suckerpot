import { Compass } from "lucide-react"
import { useTour } from "@/app/tour"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

/** "Take the tour", in the Settings header: plays the guided tour again from its first step. */
export function TourButton({ className }: { className?: string }) {
  const { start } = useTour()
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={start}
      className={cn("text-fg-muted hover:text-fg", className)}
    >
      <Compass aria-hidden className="size-4" strokeWidth={1.85} />
      {t("tour_take")}
    </Button>
  )
}
