import * as React from "react"
import { cn } from "@/lib/utils"

/** Same heights as Button (tokens.css): `sm` in filter rows, `default` in forms. */
const INPUT_SIZE = {
  sm: "h-(--control-sm) text-xs",
  default: "h-(--control-md) text-sm",
  lg: "h-(--control-lg) text-sm",
} as const

function Input({
  className,
  type,
  size = "default",
  ...props
}: Omit<React.ComponentProps<"input">, "size"> & { size?: keyof typeof INPUT_SIZE }) {
  return (
    <input
      type={type}
      data-slot="input"
      data-size={size}
      className={cn(
        "w-full min-w-0 rounded-md border border-input bg-surface px-3 py-1 shadow-xs transition-colors duration-150 selection:bg-primary selection:text-primary-foreground file:inline-flex file:h-full file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-fg-subtle disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50",
        INPUT_SIZE[size],
        "aria-invalid:border-destructive",
        className
      )}
      {...props}
    />
  )
}

export { Input }
