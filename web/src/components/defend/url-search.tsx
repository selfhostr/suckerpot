import { Search } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { Input } from "@/components/ui/input"
import { useUrlParam } from "@/hooks/use-url-param"

/** A search box that writes its text to the URL (`?q=`) after a short pause. */
export function UrlSearch({
  label,
  placeholder,
  param = "q",
}: {
  label: string
  placeholder: string
  param?: string
}) {
  const [q, setQ] = useUrlParam(param)
  const [text, setText] = useState(q ?? "")
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (document.activeElement === inputRef.current) return
    const id = setTimeout(() => setText(q ?? ""), 0)
    return () => clearTimeout(id)
  }, [q])
  useEffect(() => {
    const clean = text.trim()
    if (clean === (q ?? "")) return
    const id = setTimeout(() => setQ(clean || null), 250)
    return () => clearTimeout(id)
  }, [text, q, setQ])
  return (
    <div className="relative w-full sm:w-64">
      <Search
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-fg-subtle"
      />
      <Input
        ref={inputRef}
        value={text}
        onChange={(e) => setText(e.target.value)}
        autoComplete="off"
        spellCheck={false}
        maxLength={100}
        placeholder={placeholder}
        aria-label={label}
        size="sm"
        className="pl-8"
      />
    </div>
  )
}
