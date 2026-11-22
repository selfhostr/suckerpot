import { useQuery } from "@tanstack/react-query"
import { formKeys, formsApi } from "@/lib/abuse-forms"

/** The form queue, polled now and then: the builder adds sources during the week. */
export function useFormQueue(enabled = true) {
  return useQuery({
    queryKey: formKeys.queue,
    queryFn: formsApi.queue,
    enabled,
    refetchInterval: 60_000,
  })
}
