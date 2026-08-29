import { useCallback, useEffect, useRef } from 'react'

type IsCurrentViewAction = () => boolean

export function useViewActionScope(): () => IsCurrentViewAction {
  const generationRef = useRef(0)

  useEffect(() => {
    generationRef.current += 1
    return () => {
      generationRef.current += 1
    }
  }, [])

  return useCallback(() => {
    const generation = generationRef.current
    return () => generationRef.current === generation
  }, [])
}
