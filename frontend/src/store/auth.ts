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
  token: localStorage.getItem('socint_token'),
  user: null,
  setToken: (token) => {
    localStorage.setItem('socint_token', token)
    set({ token })
  },
  setUser: (user) => set({ user }),
  logout: () => {
    localStorage.removeItem('socint_token')
    set({ token: null, user: null })
  },
}))
