import { createContext } from "react"

/**
 * Where a page's "?" goes when the page has a switch: the end of the switch row, which the shell
 * draws outside the page. The switch registers its slot here; `PageHeader` portals the help into
 * it, or draws the help beside the page's intro line when there is no switch.
 */
export interface HelpSlot {
  node: HTMLElement | null
  setNode: (node: HTMLElement | null) => void
}

export const HelpSlotContext = createContext<HelpSlot>({ node: null, setNode: () => undefined })
