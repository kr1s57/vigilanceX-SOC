import { useState, useEffect } from 'react'
import {
  Users,
  UserPlus,
  Pencil,
  Trash2,
  Key,
  Shield,
  ShieldOff,
  CheckCircle,
  XCircle,
  Loader2,
  Eye,
  EyeOff,
  X,
  AlertTriangle,
  Clock,
  User as UserIcon,
} from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { usersApi, User, CreateUserRequest, UpdateUserRequest } from '@/lib/api'
import { cn } from '@/lib/utils'

type ModalType = 'create' | 'edit' | 'delete' | 'resetPassword' | null

export default function UserManagement() {
  const { user: currentUser, isAdmin } = useAuth()
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Modal state
  const [modalType, setModalType] = useState<ModalType>(null)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [modalLoading, setModalLoading] = useState(false)
  const [modalError, setModalError] = useState<string | null>(null)

  // Form state
  const [formUsername, setFormUsername] = useState('')
  const [formPassword, setFormPassword] = useState('')
  const [formEmail, setFormEmail] = useState('')
  const [formRole, setFormRole] = useState<'admin' | 'audit'>('audit')
  const [formIsActive, setFormIsActive] = useState(true)
  const [showPassword, setShowPassword] = useState(false)

  // Check if user is admin
  if (!isAdmin) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 text-center max-w-md p-8">
          <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center">
            <ShieldOff className="w-8 h-8 text-red-500" />
          </div>
          <h1 className="text-2xl font-bold text-white">Access Denied</h1>
          <p className="text-zinc-400">
            Only administrators can access user management.
          </p>
        </div>
      </div>
    )
  }

  // Load users
  useEffect(() => {
    loadUsers()
  }, [])

  const loadUsers = async () => {
    try {
      setLoading(true)
      const data = await usersApi.list()
      setUsers(data.users)
      setError(null)
    } catch (err) {
      setError('Failed to load users')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  // Open modals
  const openCreateModal = () => {
    setFormUsername('')
    setFormPassword('')
    setFormEmail('')
    setFormRole('audit')
    setFormIsActive(true)
    setModalError(null)
    setModalType('create')
  }

  const openEditModal = (user: User) => {
    setSelectedUser(user)
    setFormEmail(user.email || '')
    setFormRole(user.role)
    setFormIsActive(user.is_active)
    setModalError(null)
    setModalType('edit')
  }

  const openDeleteModal = (user: User) => {
    setSelectedUser(user)
    setModalError(null)
    setModalType('delete')
  }

  const openResetPasswordModal = (user: User) => {
    setSelectedUser(user)
    setFormPassword('')
    setModalError(null)
    setModalType('resetPassword')
  }

  const closeModal = () => {
    setModalType(null)
    setSelectedUser(null)
    setModalError(null)
  }

  // Actions
  const handleCreateUser = async () => {
    if (!formUsername || !formPassword) {
      setModalError('Username and password are required')
      return
    }
    if (formPassword.length < 8) {
      setModalError('Password must be at least 8 characters')
      return
    }

    setModalLoading(true)
    try {
      const request: CreateUserRequest = {
        username: formUsername,
        password: formPassword,
        email: formEmail || undefined,
        role: formRole,
      }
      await usersApi.create(request)
      await loadUsers()
      closeModal()
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to create user'
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const axiosErr = err as { response?: { data?: { error?: string } } }
        setModalError(axiosErr.response?.data?.error || errorMsg)
      } else {
        setModalError(errorMsg)
      }
    } finally {
      setModalLoading(false)
    }
  }

  const handleUpdateUser = async () => {
    if (!selectedUser) return

    setModalLoading(true)
    try {
      const request: UpdateUserRequest = {
        email: formEmail || undefined,
        role: formRole,
        is_active: formIsActive,
      }
      await usersApi.update(selectedUser.id, request)
      await loadUsers()
      closeModal()
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to update user'
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const axiosErr = err as { response?: { data?: { error?: string } } }
        setModalError(axiosErr.response?.data?.error || errorMsg)
      } else {
        setModalError(errorMsg)
      }
    } finally {
      setModalLoading(false)
    }
  }

  const handleDeleteUser = async () => {
    if (!selectedUser) return

    setModalLoading(true)
    try {
      await usersApi.delete(selectedUser.id)
      await loadUsers()
      closeModal()
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to delete user'
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const axiosErr = err as { response?: { data?: { error?: string } } }
        setModalError(axiosErr.response?.data?.error || errorMsg)
      } else {
        setModalError(errorMsg)
      }
    } finally {
      setModalLoading(false)
    }
  }

  const handleResetPassword = async () => {
    if (!selectedUser) return
    if (!formPassword) {
      setModalError('New password is required')
      return
    }
    if (formPassword.length < 8) {
      setModalError('Password must be at least 8 characters')
      return
    }

    setModalLoading(true)
    try {
      await usersApi.resetPassword(selectedUser.id, formPassword)
      closeModal()
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to reset password'
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const axiosErr = err as { response?: { data?: { error?: string } } }
        setModalError(axiosErr.response?.data?.error || errorMsg)
      } else {
        setModalError(errorMsg)
      }
    } finally {
      setModalLoading(false)
    }
  }

  // Format date
  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'Never'
    return new Date(dateStr).toLocaleString('fr-FR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Users className="w-7 h-7 text-blue-400" />
            User Management
          </h1>
          <p className="text-zinc-400 mt-1">Manage user accounts and permissions</p>
        </div>
        <button
          onClick={openCreateModal}
          className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg flex items-center gap-2 transition-colors"
        >
          <UserPlus className="w-5 h-5" />
          Add User
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3 text-red-400">
          <AlertTriangle className="w-5 h-5" />
          {error}
        </div>
      )}

      {/* Users table */}
      <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 flex items-center justify-center">
            <Loader2 className="w-8 h-8 text-zinc-500 animate-spin" />
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-zinc-800/50">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium text-zinc-400">User</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-zinc-400">Role</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-zinc-400">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-zinc-400">Last Login</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-zinc-400">Created</th>
                <th className="px-4 py-3 text-right text-sm font-medium text-zinc-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {users.map((user) => (
                <tr key={user.id} className="hover:bg-zinc-800/30 transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className={cn(
                        "w-10 h-10 rounded-full flex items-center justify-center",
                        user.role === 'admin' ? "bg-amber-500/10" : "bg-blue-500/10"
                      )}>
                        {user.role === 'admin' ? (
                          <Shield className="w-5 h-5 text-amber-400" />
                        ) : (
                          <UserIcon className="w-5 h-5 text-blue-400" />
                        )}
                      </div>
                      <div>
                        <div className="text-white font-medium flex items-center gap-2">
                          {user.username}
                          {user.id === currentUser?.id && (
                            <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">You</span>
                          )}
                        </div>
                        {user.email && (
                          <div className="text-sm text-zinc-500">{user.email}</div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn(
                      "px-2.5 py-1 rounded-full text-xs font-medium",
                      user.role === 'admin'
                        ? "bg-amber-500/10 text-amber-400"
                        : "bg-blue-500/10 text-blue-400"
                    )}>
                      {user.role === 'admin' ? 'Administrator' : 'Audit'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn(
                      "flex items-center gap-1.5 text-sm",
                      user.is_active ? "text-green-400" : "text-red-400"
                    )}>
                      {user.is_active ? (
                        <><CheckCircle className="w-4 h-4" /> Active</>
                      ) : (
                        <><XCircle className="w-4 h-4" /> Inactive</>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-zinc-400">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-4 h-4" />
                      {formatDate(user.last_login)}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-zinc-400">
                    {formatDate(user.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => openEditModal(user)}
                        className="p-2 text-zinc-400 hover:text-white hover:bg-zinc-700 rounded-lg transition-colors"
                        title="Edit user"
                      >
                        <Pencil className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => openResetPasswordModal(user)}
                        className="p-2 text-zinc-400 hover:text-amber-400 hover:bg-zinc-700 rounded-lg transition-colors"
                        title="Reset password"
                      >
                        <Key className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => openDeleteModal(user)}
                        disabled={user.id === currentUser?.id}
                        className={cn(
                          "p-2 rounded-lg transition-colors",
                          user.id === currentUser?.id
                            ? "text-zinc-600 cursor-not-allowed"
                            : "text-zinc-400 hover:text-red-400 hover:bg-zinc-700"
                        )}
                        title={user.id === currentUser?.id ? "Cannot delete yourself" : "Delete user"}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Modals */}
      {modalType && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl w-full max-w-md m-4 shadow-2xl">
            {/* Modal header */}
            <div className="flex items-center justify-between p-4 border-b border-zinc-800">
              <h3 className="text-lg font-semibold text-white">
                {modalType === 'create' && 'Create New User'}
                {modalType === 'edit' && 'Edit User'}
                {modalType === 'delete' && 'Delete User'}
                {modalType === 'resetPassword' && 'Reset Password'}
              </h3>
              <button
                onClick={closeModal}
                className="p-1 text-zinc-400 hover:text-white rounded transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal content */}
            <div className="p-4 space-y-4">
              {/* Error */}
              {modalError && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                  {modalError}
                </div>
              )}

              {/* Create form */}
              {modalType === 'create' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-zinc-300 mb-1.5">Username</label>
                    <input
                      type="text"
                      value={formUsername}
                      onChange={(e) => setFormUsername(e.target.value)}
                      className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                      placeholder="Enter username"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-zinc-300 mb-1.5">Password</label>
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={formPassword}
                        onChange={(e) => setFormPassword(e.target.value)}
                        className="w-full px-3 py-2 pr-10 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                        placeholder="Min 8 characters"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-300"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-zinc-300 mb-1.5">Email (optional)</label>
                    <input
                      type="email"
                      value={formEmail}
                      onChange={(e) => setFormEmail(e.target.value)}
                      className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                      placeholder="user@example.com"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-zinc-300 mb-1.5">Role</label>
                    <select
                      value={formRole}
                      onChange={(e) => setFormRole(e.target.value as 'admin' | 'audit')}
                      className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                    >
                      <option value="audit">Audit (View Only)</option>
                      <option value="admin">Administrator (Full Access)</option>
                    </select>
                  </div>
                </>
              )}

              {/* Edit form */}
              {modalType === 'edit' && selectedUser && (
                <>
                  <div className="text-zinc-400 text-sm">
                    Editing user: <span className="text-white font-medium">{selectedUser.username}</span>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-zinc-300 mb-1.5">Email</label>
                    <input
                      type="email"
                      value={formEmail}
                      onChange={(e) => setFormEmail(e.target.value)}
                      className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                      placeholder="user@example.com"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-zinc-300 mb-1.5">Role</label>
                    <select
                      value={formRole}
                      onChange={(e) => setFormRole(e.target.value as 'admin' | 'audit')}
                      className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                      disabled={selectedUser.id === currentUser?.id}
                    >
                      <option value="audit">Audit (View Only)</option>
                      <option value="admin">Administrator (Full Access)</option>
                    </select>
                    {selectedUser.id === currentUser?.id && (
                      <p className="text-xs text-zinc-500 mt-1">You cannot change your own role</p>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      id="isActive"
                      checked={formIsActive}
                      onChange={(e) => setFormIsActive(e.target.checked)}
                      disabled={selectedUser.id === currentUser?.id}
                      className="w-4 h-4 rounded border-zinc-600 text-blue-500 focus:ring-blue-500/50 bg-zinc-800"
                    />
                    <label htmlFor="isActive" className="text-sm text-zinc-300">
                      Account is active
                    </label>
                  </div>
                </>
              )}

              {/* Delete confirmation */}
              {modalType === 'delete' && selectedUser && (
                <div className="text-center py-4">
                  <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Trash2 className="w-8 h-8 text-red-500" />
                  </div>
                  <p className="text-white mb-2">
                    Are you sure you want to delete user <span className="font-bold">{selectedUser.username}</span>?
                  </p>
                  <p className="text-zinc-400 text-sm">This action cannot be undone.</p>
                </div>
              )}

              {/* Reset password form */}
              {modalType === 'resetPassword' && selectedUser && (
                <>
                  <div className="text-zinc-400 text-sm">
                    Reset password for: <span className="text-white font-medium">{selectedUser.username}</span>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-zinc-300 mb-1.5">New Password</label>
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={formPassword}
                        onChange={(e) => setFormPassword(e.target.value)}
                        className="w-full px-3 py-2 pr-10 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                        placeholder="Min 8 characters"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-300"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Modal footer */}
            <div className="flex justify-end gap-3 p-4 border-t border-zinc-800">
              <button
                onClick={closeModal}
                className="px-4 py-2 text-zinc-400 hover:text-white hover:bg-zinc-800 rounded-lg transition-colors"
                disabled={modalLoading}
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (modalType === 'create') handleCreateUser()
                  else if (modalType === 'edit') handleUpdateUser()
                  else if (modalType === 'delete') handleDeleteUser()
                  else if (modalType === 'resetPassword') handleResetPassword()
                }}
                disabled={modalLoading}
                className={cn(
                  "px-4 py-2 rounded-lg font-medium flex items-center gap-2 transition-colors",
                  modalType === 'delete'
                    ? "bg-red-500 hover:bg-red-600 text-white"
                    : "bg-blue-500 hover:bg-blue-600 text-white"
                )}
              >
                {modalLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                {modalType === 'create' && 'Create User'}
                {modalType === 'edit' && 'Save Changes'}
                {modalType === 'delete' && 'Delete User'}
                {modalType === 'resetPassword' && 'Reset Password'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
