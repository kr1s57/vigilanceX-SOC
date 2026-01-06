import { create } from 'zustand'
import { eventsApi, statsApi } from '@/lib/api'
import type { Event, EventStats, EventFilters, PaginatedResponse } from '@/types'

interface EventsState {
  events: Event[]
  stats: EventStats | null
  loading: boolean
  error: string | null
  filters: EventFilters
  pagination: {
    total: number
    limit: number
    offset: number
    has_more: boolean
  }

  // Actions
  fetchEvents: () => Promise<void>
  fetchStats: () => Promise<void>
  setFilters: (filters: Partial<EventFilters>) => void
  setPage: (offset: number) => void
  reset: () => void
}

const initialFilters: EventFilters = {
  log_type: undefined,
  severity: undefined,
  action: undefined,
  search: undefined,
  limit: 50,
  offset: 0,
}

export const useEventsStore = create<EventsState>((set, get) => ({
  events: [],
  stats: null,
  loading: false,
  error: null,
  filters: initialFilters,
  pagination: {
    total: 0,
    limit: 50,
    offset: 0,
    has_more: false,
  },

  fetchEvents: async () => {
    set({ loading: true, error: null })
    try {
      const { filters } = get()
      const response = await eventsApi.list(filters)
      set({
        events: response.data,
        pagination: response.pagination,
        loading: false,
      })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to fetch events',
        loading: false,
      })
    }
  },

  fetchStats: async () => {
    try {
      const stats = await statsApi.overview()
      set({ stats })
    } catch (err) {
      console.error('Failed to fetch stats:', err)
    }
  },

  setFilters: (newFilters: Partial<EventFilters>) => {
    set((state) => ({
      filters: { ...state.filters, ...newFilters, offset: 0 },
      pagination: { ...state.pagination, offset: 0 },
    }))
    get().fetchEvents()
  },

  setPage: (offset: number) => {
    set((state) => ({
      filters: { ...state.filters, offset },
      pagination: { ...state.pagination, offset },
    }))
    get().fetchEvents()
  },

  reset: () => {
    set({
      events: [],
      stats: null,
      loading: false,
      error: null,
      filters: initialFilters,
      pagination: { total: 0, limit: 50, offset: 0, has_more: false },
    })
  },
}))
