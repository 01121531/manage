import { UserManager, WebStorageStateStore } from 'oidc-client-ts'
import type { AuthConfig } from './types'

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>()
  get length() { return this.values.size }
  clear() { this.values.clear() }
  getItem(key: string) { return this.values.get(key) ?? null }
  key(index: number) { return [...this.values.keys()][index] ?? null }
  removeItem(key: string) { this.values.delete(key) }
  setItem(key: string, value: string) { this.values.set(key, value) }
}

export function createOidcManager(config: AuthConfig): UserManager {
  if (!config.issuer || !config.client_id) {
    throw new Error('OIDC 公共配置不完整')
  }
  return new UserManager({
    authority: config.issuer,
    client_id: config.client_id,
    redirect_uri: `${window.location.origin}/callback`,
    post_logout_redirect_uri: `${window.location.origin}/`,
    response_type: 'code',
    scope: 'openid profile email',
    loadUserInfo: false,
    automaticSilentRenew: false,
    stateStore: new WebStorageStateStore({ store: window.sessionStorage, prefix: 'oidc.state.' }),
    userStore: new WebStorageStateStore({ store: new MemoryStorage(), prefix: 'oidc.user.' }),
  })
}
