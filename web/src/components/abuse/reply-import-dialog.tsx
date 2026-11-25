import { useQueryClient } from "@tanstack/react-query"
import { useId, useRef, useState, type SyntheticEvent } from "react"
import { Field, FormError } from "@/components/form-parts"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Textarea } from "@/components/ui/textarea"
import { t } from "@/i18n"
import { abuseKeys } from "@/lib/abuse"
import { describeRepliesError, repliesApi } from "@/lib/replies"

const MAX_BYTES = 256 * 1024
const MAX_LABEL = "256 KiB"

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Public id of the report the reply belongs to, when known. */
  report?: string
}

/** "Add a reply": paste the whole message with its headers, or pick an .eml file. Text only. */
export function ReplyImportDialog({ open, onOpenChange, report }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        {open ? <ImportForm onOpenChange={onOpenChange} report={report} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function ImportForm({ onOpenChange, report }: Omit<Props, "open">) {
  const id = useId()
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [raw, setRaw] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function pick(file: File | undefined) {
    if (!file) return
    if (file.size > MAX_BYTES) {
      setError(t("replies_import_file_too_large", { size: MAX_LABEL }))
      return
    }
    setError(null)
    setRaw(await file.text())
  }

  async function submit() {
    if (!raw.trim()) {
      setError(t("replies_import_empty", { ext: ".eml" }))
      return
    }
    if (new Blob([raw]).size > MAX_BYTES) {
      setError(t("replies_error_too_large", { size: MAX_LABEL }))
      return
    }
    setPending(true)
    setError(null)
    try {
      const { id: importId } = await repliesApi.importReply(raw, report)
      // The worker parses it within a moment; wait for the verdict, but not for ever.
      for (let i = 0; i < 15; i++) {
        const s = await repliesApi.importState(importId)
        if (s.status === "failed") {
          setError(
            s.error_code === "not_a_message"
              ? t("replies_error_not_a_message")
              : t("replies_import_unreadable"),
          )
          return
        }
        if (s.status === "done") break
        await new Promise((r) => setTimeout(r, 800))
      }
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
      onOpenChange(false)
    } catch (e) {
      setError(describeRepliesError(e))
    } finally {
      setPending(false)
    }
  }

  return (
    <form
      noValidate
      className="flex flex-col gap-4"
      onSubmit={(e: SyntheticEvent) => {
        e.preventDefault()
        void submit()
      }}
    >
      <DialogHeader className="text-left">
        <DialogTitle>{t("replies_import_title")}</DialogTitle>
        <DialogDescription>{t("replies_import_description", { ext: ".eml" })}</DialogDescription>
      </DialogHeader>
      <Field
        id={id}
        label={t("replies_import_message")}
        hint={t("replies_import_hint", { size: MAX_LABEL })}
      >
        <Textarea
          id={id}
          rows={9}
          value={raw}
          spellCheck={false}
          autoComplete="off"
          className="font-mono text-xs"
          placeholder={"From: abuse@example.net\nSubject: Re: ...\n\nBody"}
          onChange={(e) => setRaw(e.target.value)}
        />
      </Field>
      <div>
        <input
          ref={fileRef}
          type="file"
          accept=".eml,message/rfc822"
          className="sr-only"
          aria-label={t("replies_import_pick", { ext: ".eml" })}
          onChange={(e) => void pick(e.target.files?.[0])}
        />
        <Button type="button" variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
          {t("replies_import_pick", { ext: ".eml" })}
        </Button>
      </div>
      <FormError id={`${id}-err`} message={error} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
          {t("common_cancel")}
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? t("replies_import_reading") : t("replies_import_submit")}
        </Button>
      </DialogFooter>
    </form>
  )
}
