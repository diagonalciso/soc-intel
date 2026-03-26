import { create } from 'zustand'

interface User {
  id: string
  email: string
  username: string
  role: string
}

interface AuthState {
  token: string | null
  user: User | null
  setToken: (token: string) => void
  setUser: (user: User) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem('clawint_token'),
  user: null,
  setToken: (token) => {
    localStorage.setItem('clawint_token', token)
    set({ token })
  },
  setUser: (user) => set({ user }),
  logout: () => {
    localStorage.removeItem('clawint_token')
    set({ token: null, user: null })
  },
}))
