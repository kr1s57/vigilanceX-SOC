import { create } from 'zustand'
import { bansApi } from '@/lib/api'
import type { BanStatus, BanStats } from '@/types'

interface BansState {
  bans: BanStatus[]
  stats: BanStats | null
  loading: boolean
  syncing: boolean
  error: string | null

  // Actions
  fetchBans: () => Promise<void>
  fetchStats: () => Promise<void>
  banIP: (ip: string, reason: string, duration?: number) => Promise<void>
  unbanIP: (ip: string) => Promise<void>
  extendBan: (ip: string, duration: number) => Promise<void>
  makePermanent: (ip: string) => Promise<void>
  syncXGS: () => Promise<void>
  reset: () => void
}

export const useBansStore = create<BansState>((set, get) => ({
  bans: [],
  stats: null,
  loading: false,
  syncing: false,
  error: null,

  fetchBans: async () => {
    set({ loading: true, error: null })
    try {
      const bans = await bansApi.list()
      set({ bans, loading: false })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to fetch bans',
        loading: false,
      })
    }
  },

  fetchStats: async () => {
    try {
      const stats = await bansApi.stats()
      set({ stats })
    } catch (err) {
      console.error('Failed to fetch ban stats:', err)
    }
  },

  banIP: async (ip: string, reason: string, duration?: number) => {
    set({ loading: true, error: null })
    try {
      await bansApi.create({ ip, reason, duration })
      await get().fetchBans()
      await get().fetchStats()
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to ban IP',
        loading: false,
      })
      throw err
    }
  },

  unbanIP: async (ip: string) => {
    set({ loading: true, error: null })
    try {
      await bansApi.delete(ip)
      await get().fetchBans()
      await get().fetchStats()
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to unban IP',
        loading: false,
      })
      throw err
    }
  },

  extendBan: async (ip: string, duration: number) => {
    set({ loading: true, error: null })
    try {
      await bansApi.extend(ip, duration)
      await get().fetchBans()
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to extend ban',
        loading: false,
      })
      throw err
    }
  },

  makePermanent: async (ip: string) => {
    set({ loading: true, error: null })
    try {
      await bansApi.makePermanent(ip)
      await get().fetchBans()
      await get().fetchStats()
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to make ban permanent',
        loading: false,
      })
      throw err
    }
  },

  syncXGS: async () => {
    set({ syncing: true, error: null })
    try {
      await bansApi.sync()
      await get().fetchBans()
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to sync with XGS',
        syncing: false,
      })
      throw err
    } finally {
      set({ syncing: false })
    }
  },

  reset: () => {
    set({
      bans: [],
      stats: null,
      loading: false,
      syncing: false,
      error: null,
    })
  },
}))
