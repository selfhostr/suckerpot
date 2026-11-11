import { useQuery } from "@tanstack/react-query"
import { fetchPipeline, pipelineKey, UNKNOWN_PIPELINE, type PipelineStatus } from "@/lib/pipeline"

/** Pipeline health, polled once a minute and shared by the banner and Settings. */
export function usePipeline(): { pipeline: PipelineStatus; loading: boolean } {
  const q = useQuery({
    queryKey: pipelineKey,
    queryFn: fetchPipeline,
    refetchInterval: 60_000,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
    retry: false,
  })
  return { pipeline: q.data ?? UNKNOWN_PIPELINE, loading: q.isPending }
}
