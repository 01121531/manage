import { useCallback, useEffect, useRef } from 'react'
import { App as AntApp, type ModalFuncProps } from 'antd'

type Confirm = ReturnType<typeof AntApp.useApp>['modal']['confirm']
type ConfirmInstance = ReturnType<Confirm>

export function useScopedConfirm(): Confirm {
  const { modal } = AntApp.useApp()
  const instancesRef = useRef(new Set<ConfirmInstance>())

  useEffect(() => () => {
    const instances = [...instancesRef.current]
    instancesRef.current.clear()
    for (const instance of instances) instance.destroy()
  }, [])

  return useCallback<Confirm>((props: ModalFuncProps) => {
    const callerAfterClose = props.afterClose
    let closed = false
    let instance: ConfirmInstance | undefined
    instance = modal.confirm({
      ...props,
      afterClose: () => {
        closed = true
        if (instance) instancesRef.current.delete(instance)
        callerAfterClose?.()
      },
    })
    if (!closed) instancesRef.current.add(instance)
    return instance
  }, [modal])
}
