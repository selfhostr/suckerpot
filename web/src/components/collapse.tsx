import { useState } from "react"

interface CollapseProps {
  open: boolean
  id?: string
  className?: string
  children: React.ReactNode
}

/**
 * The panel of a disclosure: it opens and closes with a height animation (grid rows from 0fr to
 * 1fr, index.css `.collapse-panel`). The content mounts on the first open and stays, hidden and
 * inert, after it closes, so closing can animate too.
 */
export function Collapse({ open, id, className, children }: CollapseProps) {
  const [opened, setOpened] = useState(open)
  if (open && !opened) setOpened(true)
  return (
    <div id={id} data-open={open ? "" : undefined} inert={!open} className="collapse-panel">
      <div>{opened ? <div className={className}>{children}</div> : null}</div>
    </div>
  )
}
