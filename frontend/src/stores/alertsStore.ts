// v3.58.100: Global alerts store for badges and notifications
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AlertsState {
  // Vigimail new leaks badge
  vigimailNewLeaks: number
  vigimailLastSeen: string | null // ISO date when user last viewed vigimail

  // Actions
  setVigimailNewLeaks: (count: number) => void
  incrementVigimailNewLeaks: (count?: number) => void
  markVigimailSeen: () => void
  clearVigimailBadge: () => void
}

export const useAlertsStore = create<AlertsState>()(
  persist(
    (set) => ({
      vigimailNewLeaks: 0,
      vigimailLastSeen: null,

      setVigimailNewLeaks: (count) => set({ vigimailNewLeaks: count }),

      incrementVigimailNewLeaks: (count = 1) =>
        set((state) => ({ vigimailNewLeaks: state.vigimailNewLeaks + count })),

      markVigimailSeen: () =>
        set({
          vigimailNewLeaks: 0,
          vigimailLastSeen: new Date().toISOString()
        }),

      clearVigimailBadge: () => set({ vigimailNewLeaks: 0 }),
    }),
    {
      name: 'vgx-alerts',
    }
  )
)
