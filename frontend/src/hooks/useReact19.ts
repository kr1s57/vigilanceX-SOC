import { useState, useTransition, useDeferredValue, useCallback, useOptimistic } from 'react'

/**
 * React 18/19 Hooks for VIGILANCE X
 * v3.58.108: Modern React patterns for better UX
 */

/**
 * useDeferredSearch - Deferred search input for expensive filtering
 * Prevents UI jank when filtering large lists
 */
export function useDeferredSearch(initialValue: string = '') {
  const [searchValue, setSearchValue] = useState(initialValue)
  const deferredSearch = useDeferredValue(searchValue)
  const isStale = searchValue !== deferredSearch

  return {
    searchValue,
    setSearchValue,
    deferredSearch,
    isStale,
  }
}

/**
 * useTransitionState - State with transition for non-urgent updates
 * Shows pending state during expensive operations
 */
export function useTransitionState<T>(initialValue: T) {
  const [value, setValue] = useState(initialValue)
  const [isPending, startTransition] = useTransition()

  const setValueWithTransition = useCallback((newValue: T | ((prev: T) => T)) => {
    startTransition(() => {
      setValue(newValue)
    })
  }, [])

  return {
    value,
    setValue: setValueWithTransition,
    setValueImmediate: setValue,
    isPending,
  }
}

/**
 * usePagination - Pagination with transitions
 * Smooth page changes without blocking UI
 */
export function usePagination(initialPage: number = 1, initialPageSize: number = 25) {
  const [page, setPageInternal] = useState(initialPage)
  const [pageSize, setPageSizeInternal] = useState(initialPageSize)
  const [isPending, startTransition] = useTransition()

  const setPage = useCallback((newPage: number) => {
    startTransition(() => {
      setPageInternal(newPage)
    })
  }, [])

  const setPageSize = useCallback((newSize: number) => {
    startTransition(() => {
      setPageSizeInternal(newSize)
      setPageInternal(1) // Reset to first page when changing page size
    })
  }, [])

  const nextPage = useCallback(() => {
    startTransition(() => {
      setPageInternal(p => p + 1)
    })
  }, [])

  const prevPage = useCallback(() => {
    startTransition(() => {
      setPageInternal(p => Math.max(1, p - 1))
    })
  }, [])

  const goToPage = useCallback((targetPage: number) => {
    startTransition(() => {
      setPageInternal(Math.max(1, targetPage))
    })
  }, [])

  return {
    page,
    pageSize,
    setPage,
    setPageSize,
    nextPage,
    prevPage,
    goToPage,
    isPending,
  }
}

/**
 * useOptimisticList - Optimistic updates for list operations
 * Shows immediate feedback while waiting for server response
 */
export function useOptimisticList<T extends { id: string | number }>(initialList: T[]) {
  const [list, setList] = useState(initialList)
  const [optimisticList, addOptimistic] = useOptimistic(
    list,
    (currentList: T[], action: { type: 'add' | 'remove' | 'update'; item: T }) => {
      switch (action.type) {
        case 'add':
          return [...currentList, action.item]
        case 'remove':
          return currentList.filter(item => item.id !== action.item.id)
        case 'update':
          return currentList.map(item =>
            item.id === action.item.id ? action.item : item
          )
        default:
          return currentList
      }
    }
  )

  const optimisticAdd = useCallback((item: T) => {
    addOptimistic({ type: 'add', item })
  }, [addOptimistic])

  const optimisticRemove = useCallback((item: T) => {
    addOptimistic({ type: 'remove', item })
  }, [addOptimistic])

  const optimisticUpdate = useCallback((item: T) => {
    addOptimistic({ type: 'update', item })
  }, [addOptimistic])

  return {
    list: optimisticList,
    setList,
    optimisticAdd,
    optimisticRemove,
    optimisticUpdate,
  }
}

/**
 * useAsyncAction - Async action with loading and error states
 * Combines useTransition with async operations
 */
export function useAsyncAction<T, Args extends unknown[]>(
  action: (...args: Args) => Promise<T>
) {
  const [isPending, startTransition] = useTransition()
  const [error, setError] = useState<Error | null>(null)
  const [data, setData] = useState<T | null>(null)

  const execute = useCallback(async (...args: Args) => {
    setError(null)

    return new Promise<T>((resolve, reject) => {
      startTransition(async () => {
        try {
          const result = await action(...args)
          setData(result)
          resolve(result)
        } catch (err) {
          const error = err instanceof Error ? err : new Error('Unknown error')
          setError(error)
          reject(error)
        }
      })
    })
  }, [action])

  return {
    execute,
    isPending,
    error,
    data,
    reset: () => {
      setError(null)
      setData(null)
    },
  }
}

/**
 * useFilter - Deferred filtering for large datasets
 * Combines useDeferredValue with filter function
 */
export function useFilter<T>(
  items: T[],
  filterFn: (item: T, search: string) => boolean,
  initialSearch: string = ''
) {
  const { searchValue, setSearchValue, deferredSearch, isStale } = useDeferredSearch(initialSearch)

  const filteredItems = items.filter(item => filterFn(item, deferredSearch))

  return {
    searchValue,
    setSearchValue,
    filteredItems,
    isFiltering: isStale,
    totalCount: items.length,
    filteredCount: filteredItems.length,
  }
}

/**
 * useTabTransition - Tab switching with transitions
 * Prevents flash of loading state for fast tab switches
 */
export function useTabTransition<T extends string>(initialTab: T) {
  const [activeTab, setActiveTabInternal] = useState(initialTab)
  const [isPending, startTransition] = useTransition()

  const setActiveTab = useCallback((tab: T) => {
    startTransition(() => {
      setActiveTabInternal(tab)
    })
  }, [])

  return {
    activeTab,
    setActiveTab,
    isPending,
  }
}
