import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
import {
  Ban,
  CircleCheck,
  CircleDashed,
  Ellipsis,
  Eye,
  KeyRound,
  Lock,
  LockOpen,
  LogOut,
  ShieldCheck,
  Trash2,
  UserCheck,
  UserCog,
  UserPlus,
  type LucideIcon,
} from "lucide-react"
import { useMemo, useState } from "react"
import { useAuth } from "@/app/auth"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonText } from "@/components/skeletons"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { queryKeys } from "@/lib/api"
import type { Role } from "@/lib/auth-api"
import {
  deleteUser,
  resetUserPassword,
  revokeUserSessions,
  ROLE_HINT,
  ROLE_LABEL,
  ROLE_OPTIONS,
  STATE_LABEL,
  unlockUser,
  updateUser,
  userState,
  usersApi,
  usersFinding,
  type UserItem,
  type UserState,
} from "@/lib/users"
import { cn } from "@/lib/utils"
import { AdminActionDialog } from "./admin-action-dialog"
import { AddUserDialog } from "./add-user-dialog"
import { TemporaryPasswordDialog, type Reveal } from "./temporary-password-dialog"

const STATE_STYLE: Record<UserState, { icon: LucideIcon; className: string }> = {
  active: { icon: CircleCheck, className: "text-status-ok" },
  pending: { icon: CircleDashed, className: "text-fg-muted" },
  locked: { icon: Lock, className: "text-sev-warning" },
  disabled: { icon: Ban, className: "text-fg-muted" },
}

/** Role as a neutral badge: a shield for those who can change things, an eye for viewers. */
function RoleBadge({ user }: { user: UserItem }) {
  const admin = user.is_owner || user.role === "admin"
  const Icon = admin ? ShieldCheck : Eye
  return (
    <Badge variant="outline" className={cn("rounded-sm", admin ? "text-fg" : "text-fg-muted")}>
      <Icon aria-hidden className="size-3" />
      {user.is_owner ? "Owner" : ROLE_LABEL[user.role]}
    </Badge>
  )
}

function StateLabel({ user }: { user: UserItem }) {
  const state = userState(user)
  const { icon: Icon, className } = STATE_STYLE[state]
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", className)}>
      <Icon aria-hidden className="size-3.5" strokeWidth={2.25} />
      {STATE_LABEL[state]}
    </span>
  )
}

type ActionKind = "role" | "disable" | "enable" | "reset" | "unlock" | "revoke" | "delete"

interface Pending {
  kind: ActionKind
  user: UserItem
}

function RoleField({ value, onChange }: { value: Role; onChange: (role: Role) => void }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-sm font-medium text-fg">Role</span>
      <SegmentedControl
        label="Role"
        value={value}
        onChange={onChange}
        options={ROLE_OPTIONS}
        className="self-start"
      />
      <p className="text-xs text-fg-muted">{ROLE_HINT[value]}</p>
    </div>
  )
}

/** The dialog for one row action. Mounted per action, so its state starts fresh each time. */
function ActionDialog({
  pending,
  onClose,
  onChanged,
  onReveal,
}: {
  pending: Pending
  onClose: () => void
  onChanged: () => void
  onReveal: (reveal: Reveal) => void
}) {
  const { kind, user } = pending
  const id = user.id ?? 0
  const name = user.display_name
  const [role, setRole] = useState<Role>(user.role === "admin" ? "viewer" : "admin")
  const common = {
    open: true,
    onOpenChange: (open: boolean) => !open && onClose(),
    onDone: onChanged,
  }
  switch (kind) {
    case "role":
      return (
        <AdminActionDialog
          {...common}
          title={`Change the role of ${name}`}
          description="They are signed out and sign in again with the new role."
          confirmLabel="Change role"
          pendingLabel="Saving…"
          run={(password) => updateUser(id, { role }, password)}
          validate={() => (role === user.role ? "That is already their role." : null)}
        >
          <RoleField value={role} onChange={setRole} />
        </AdminActionDialog>
      )
    case "disable":
      return (
        <AdminActionDialog
          {...common}
          title={`Disable ${name}`}
          description="They are signed out now and cannot sign in until you enable the account again."
          confirmLabel="Disable"
          pendingLabel="Disabling…"
          run={(password) => updateUser(id, { disabled: true }, password)}
        />
      )
    case "enable":
      return (
        <AdminActionDialog
          {...common}
          title={`Enable ${name}`}
          description="They can sign in again with their current password."
          confirmLabel="Enable"
          pendingLabel="Enabling…"
          run={(password) => updateUser(id, { disabled: false }, password)}
        />
      )
    case "reset":
      return (
        <AdminActionDialog
          {...common}
          title={`Reset the password of ${name}`}
          description="They are signed out. You get a new temporary password to hand over, and they must choose their own at the next sign-in."
          confirmLabel="Reset password"
          pendingLabel="Resetting…"
          run={async (password) => {
            const { temporary } = await resetUserPassword(id, password)
            onReveal({
              username: user.username,
              display_name: user.display_name,
              temporary,
              kind: "reset",
            })
          }}
        />
      )
    case "unlock":
      return (
        <AdminActionDialog
          {...common}
          title={`Unlock ${name}`}
          description="The account was locked after too many wrong passwords. Unlocking lets them try again now."
          confirmLabel="Unlock"
          pendingLabel="Unlocking…"
          run={(password) => unlockUser(id, password)}
        />
      )
    case "revoke":
      return (
        <AdminActionDialog
          {...common}
          title={`Sign ${name} out everywhere`}
          description="Every browser where they are signed in is signed out at once. Their password stays the same."
          confirmLabel="Sign out everywhere"
          pendingLabel="Signing out…"
          run={(password) => revokeUserSessions(id, password)}
        />
      )
    case "delete":
      return (
        <AdminActionDialog
          {...common}
          title={`Delete ${name}`}
          description="The account is removed for good and they are signed out now. Entries about them stay in the audit log."
          confirmLabel="Delete user"
          pendingLabel="Deleting…"
          run={(password) => deleteUser(id, password)}
        />
      )
  }
}

function RowActions({
  user,
  isYou,
  onPick,
}: {
  user: UserItem
  isYou: boolean
  onPick: (kind: ActionKind) => void
}) {
  const state = userState(user)
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          aria-label={`Actions for ${user.username}`}
          className="size-8"
        >
          <Ellipsis aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        {isYou ? (
          <>
            <DropdownMenuLabel className="text-xs font-normal text-fg-muted">
              This is you. Change your own password from the account menu.
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
          </>
        ) : null}
        <DropdownMenuItem disabled={isYou} onSelect={() => onPick("role")}>
          <UserCog aria-hidden />
          Change role
        </DropdownMenuItem>
        {state === "disabled" ? (
          <DropdownMenuItem onSelect={() => onPick("enable")}>
            <UserCheck aria-hidden />
            Enable
          </DropdownMenuItem>
        ) : (
          <DropdownMenuItem disabled={isYou} onSelect={() => onPick("disable")}>
            <Ban aria-hidden />
            Disable
          </DropdownMenuItem>
        )}
        {state === "locked" ? (
          <DropdownMenuItem onSelect={() => onPick("unlock")}>
            <LockOpen aria-hidden />
            Unlock
          </DropdownMenuItem>
        ) : null}
        <DropdownMenuItem disabled={isYou} onSelect={() => onPick("reset")}>
          <KeyRound aria-hidden />
          Reset password
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onPick("revoke")}>
          <LogOut aria-hidden />
          Sign out everywhere
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem disabled={isYou} onSelect={() => onPick("delete")}>
          <Trash2 aria-hidden />
          Delete user
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function UserRow({
  user,
  isYou,
  onPick,
}: {
  user: UserItem
  isYou: boolean
  onPick: (kind: ActionKind) => void
}) {
  return (
    <li className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-2 px-4 py-3 sm:px-5 lg:grid-cols-[minmax(0,1.4fr)_9rem_12rem_minmax(0,1fr)_2rem]">
      <div className="min-w-0">
        <p
          className={cn(
            "flex items-center gap-2 text-sm font-medium",
            user.disabled ? "text-fg-muted" : "text-fg",
          )}
        >
          <span className="truncate">{user.display_name}</span>
          {isYou ? <span className="text-xs font-normal text-fg-muted">(you)</span> : null}
        </p>
        <p className="truncate font-mono text-xs text-fg-muted">{user.username}</p>
      </div>
      <div className="col-start-1 row-start-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 lg:contents">
        <span className="lg:col-start-2 lg:row-start-1">
          <RoleBadge user={user} />
        </span>
        <span className="lg:col-start-3 lg:row-start-1">
          {user.is_owner ? (
            <span className="text-xs text-fg-muted">Set in .env</span>
          ) : (
            <StateLabel user={user} />
          )}
        </span>
        <span className="text-xs text-fg-muted lg:col-start-4 lg:row-start-1">
          {user.last_login_at ? (
            <>
              Last sign-in <RelativeTime iso={user.last_login_at} className="text-xs" />
            </>
          ) : (
            "Never signed in"
          )}
          {user.created_at ? (
            <>
              {" "}
              · added <RelativeTime iso={user.created_at} className="text-xs" />
            </>
          ) : null}
        </span>
      </div>
      <div className="col-start-2 row-start-1 justify-self-end lg:col-start-5">
        {user.is_owner ? null : <RowActions user={user} isYou={isYou} onPick={onPick} />}
      </div>
    </li>
  )
}

/** Administrators only: who can sign in, and what each account may do. */
export function UsersCard() {
  const { user: me } = useAuth()
  const client = useQueryClient()
  const [pending, setPending] = useState<Pending | null>(null)
  const [reveal, setReveal] = useState<Reveal | null>(null)

  const q = useInfiniteQuery({
    queryKey: queryKeys.users,
    queryFn: ({ pageParam }) => usersApi.list(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const list = useMemo(() => {
    const first = q.data?.pages[0]
    if (!first) return null
    return { ...first, items: (q.data?.pages ?? []).flatMap((p) => p.items) }
  }, [q.data])

  function changed() {
    void client.invalidateQueries({ queryKey: queryKeys.users })
    void client.invalidateQueries({ queryKey: ["audit"] })
  }

  const rows = list ? [list.owner, ...list.items] : []
  return (
    <>
      <FindingCard
        eyebrow="Users"
        finding={list ? usersFinding(list) : "Checking who can sign in…"}
        detail="The owner is set in .env and always an administrator. Everyone else is managed here."
        action={
          <AddUserDialog
            onCreated={(r) => {
              setReveal(r)
              changed()
            }}
            trigger={
              <Button size="sm">
                <UserPlus aria-hidden />
                Add user
              </Button>
            }
          />
        }
        bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
      >
        {q.isPending ? (
          <div className="px-4 sm:px-5">
            <SkeletonText lines={4} className="py-1" />
          </div>
        ) : !list ? (
          <p className="px-4 pb-3 text-sm text-fg-muted sm:px-5">
            The users are not available right now.
          </p>
        ) : (
          <>
            <ul aria-label="Users" className="divide-y border-t">
              {rows.map((u) => (
                <UserRow
                  key={u.id ?? "owner"}
                  user={u}
                  isYou={me?.username.toLowerCase() === u.username.toLowerCase()}
                  onPick={(kind) => setPending({ kind, user: u })}
                />
              ))}
            </ul>
            <LoadMore
              hasNextPage={q.hasNextPage}
              isFetchingNextPage={q.isFetchingNextPage}
              fetchNextPage={q.fetchNextPage}
              label="Show more users"
              className="border-t"
            />
          </>
        )}
      </FindingCard>
      {pending ? (
        <ActionDialog
          key={`${pending.kind}-${pending.user.id}`}
          pending={pending}
          onClose={() => setPending(null)}
          onChanged={changed}
          onReveal={(r) => {
            setReveal(r)
            changed()
          }}
        />
      ) : null}
      <TemporaryPasswordDialog reveal={reveal} onClose={() => setReveal(null)} />
    </>
  )
}
