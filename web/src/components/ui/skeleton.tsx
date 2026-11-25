import { cn } from "@/lib/utils"

/** A placeholder in the final shape of its content, with a soft sweep (index.css `.skeleton`). */
function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return <div data-slot="skeleton" className={cn("skeleton rounded-md", className)} {...props} />
}

export { Skeleton }
