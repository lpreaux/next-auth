/**
 *
 * :::warning
 * `@auth/angular` is currently experimental. The API _will_ change in the future.
 * :::
 *
 * Angular Auth is the official Angular integration for Auth.js.
 * It provides a simple way to add authentication to your Angular app in a few lines of code.
 *
 * ## Installation
 * ```bash npm2yarn
 * npm install @auth/angular
 * ```
 *
 * ## Usage
 *
 * ### Setup
 *
 * First, create an auth configuration file:
 *
 * ```ts title="src/app/auth.config.ts"
 * import type { AuthConfig } from "@auth/angular"
 * import GitHub from "@auth/angular/providers/github"
 *
 * export const authConfig: AuthConfig = {
 *   providers: [
 *     GitHub({
 *       clientId: process.env['AUTH_GITHUB_ID'],
 *       clientSecret: process.env['AUTH_GITHUB_SECRET'],
 *     })
 *   ],
 *   secret: process.env['AUTH_SECRET'],
 *   trustHost: true,
 * }
 * ```
 *
 * ### Provider Setup
 *
 * Add the AngularAuth provider to your app configuration:
 *
 * ```ts title="src/app/app.config.ts"
 * import { ApplicationConfig } from '@angular/core'
 * import { provideRouter } from '@angular/router'
 * import { provideAngularAuth } from '@auth/angular'
 * import { authConfig } from './auth.config'
 *
 * export const appConfig: ApplicationConfig = {
 *   providers: [
 *     provideRouter(routes),
 *     provideAngularAuth(authConfig),
 *     // ... other providers
 *   ],
 * }
 * ```
 *
 * ### API Route Handler
 *
 * Create an API route to handle authentication requests. If using Angular Universal with Express:
 *
 * ```ts title="server.ts"
 * import { Auth } from "@auth/core"
 * import { authConfig } from "./src/app/auth.config"
 *
 * app.use('/api/auth/*', async (req, res) => {
 *   const request = new Request(`${req.protocol}://${req.get('host')}${req.originalUrl}`, {
 *     method: req.method,
 *     headers: req.headers as any,
 *     body: req.method !== 'GET' && req.method !== 'HEAD' ? JSON.stringify(req.body) : undefined,
 *   })
 *
 *   const response = await Auth(request, authConfig)
 *
 *   res.status(response.status)
 *   response.headers.forEach((value, key) => {
 *     res.setHeader(key, value)
 *   })
 *
 *   const body = await response.text()
 *   res.send(body)
 * })
 * ```
 *
 * ### Using the Session Service
 *
 * ```ts title="src/app/components/profile.component.ts"
 * import { Component } from '@angular/core'
 * import { AuthService, type Session } from '@auth/angular'
 * import { Observable } from 'rxjs'
 *
 * @Component({
 *   selector: 'app-profile',
 *   template: `
 *     <div *ngIf="session$ | async as session; else signedOut">
 *       <p>Welcome, {{ session.user?.name }}!</p>
 *       <img [src]="session.user?.image" [alt]="session.user?.name">
 *       <button (click)="signOut()">Sign Out</button>
 *     </div>
 *     <ng-template #signedOut>
 *       <p>You are not signed in</p>
 *       <button (click)="signIn('github')">Sign In with GitHub</button>
 *     </ng-template>
 *   `
 * })
 * export class ProfileComponent {
 *   session$: Observable<Session | null>
 *
 *   constructor(private authService: AuthService) {
 *     this.session$ = this.authService.session$
 *   }
 *
 *   signIn(provider: string) {
 *     this.authService.signIn(provider)
 *   }
 *
 *   signOut() {
 *     this.authService.signOut()
 *   }
 * }
 * ```
 *
 * ### Route Guards
 *
 * Create a guard to protect routes:
 *
 * ```ts title="src/app/guards/auth.guard.ts"
 * import { Injectable } from '@angular/core'
 * import { CanActivate, Router } from '@angular/router'
 * import { AuthService } from '@auth/angular'
 * import { map, take } from 'rxjs/operators'
 *
 * @Injectable({
 *   providedIn: 'root'
 * })
 * export class AuthGuard implements CanActivate {
 *   constructor(
 *     private authService: AuthService,
 *     private router: Router
 *   ) {}
 *
 *   canActivate() {
 *     return this.authService.session$.pipe(
 *       take(1),
 *       map(session => {
 *         if (session?.user) {
 *           return true
 *         } else {
 *           this.router.navigate(['/auth/signin'])
 *           return false
 *         }
 *       })
 *     )
 *   }
 * }
 * ```
 *
 * ## Features
 *
 * - **Session Management**: Reactive session state with RxJS observables
 * - **Route Protection**: Angular guards for protecting routes
 * - **Sign In/Out**: Simple methods for authentication
 * - **Provider Support**: Support for all Auth.js providers
 * - **TypeScript**: Full TypeScript support with proper types
 * - **SSR Ready**: Compatible with Angular Universal
 *
 * @module @auth/angular
 */

import { Injectable, InjectionToken, inject, PLATFORM_ID } from "@angular/core"
import { isPlatformBrowser } from "@angular/common"
import { BehaviorSubject, Observable, from, of } from "rxjs"
import { switchMap, tap, catchError } from "rxjs/operators"
import type { AuthConfig } from "@auth/core"
import type { Session, User, Account, Profile } from "@auth/core/types"
import type { ProviderId } from "@auth/core/providers"

// Re-export types from Auth.js core
export type {
  Account,
  DefaultSession,
  Profile,
  Session,
  User,
} from "@auth/core/types"

export { AuthError, CredentialsSignin } from "@auth/core/errors"

// Configuration token
export const ANGULAR_AUTH_CONFIG = new InjectionToken<AngularAuthConfig>(
  "ANGULAR_AUTH_CONFIG"
)

// Angular-specific auth config
export interface AngularAuthConfig extends Omit<AuthConfig, "raw"> {
  /**
   * Base path for auth API routes
   * @default '/api/auth'
   */
  basePath?: string
}

// Sign in options interface
export interface SignInOptions<Redirect extends boolean = true>
  extends Record<string, unknown> {
  /**
   * Specify where the user should be redirected to after a successful signin.
   */
  redirectTo?: string
  /**
   * You might want to deal with the signin response on the same page, instead of redirecting.
   */
  redirect?: Redirect
}

// Sign in response interface
export interface SignInResponse {
  error: string | undefined
  code: string | undefined
  status: number
  ok: boolean
  url: string | null
}

// Sign out options interface
export interface SignOutOptions<Redirect extends boolean = true> {
  /**
   * Specify where the user should be redirected to after signing out.
   */
  redirectTo?: string
  /**
   * If you pass `redirect: false`, the page will not reload.
   */
  redirect?: Redirect
}

/**
 * Main service for handling authentication in Angular applications
 */
@Injectable({
  providedIn: "root",
})
export class AuthService {
  private config = inject(ANGULAR_AUTH_CONFIG)
  private platformId = inject(PLATFORM_ID)
  private basePath = this.config.basePath || "/api/auth"

  private sessionSubject = new BehaviorSubject<Session | null>(null)
  private loadingSubject = new BehaviorSubject<boolean>(true)

  /**
   * Observable of the current session state
   */
  public readonly session$: Observable<Session | null> =
    this.sessionSubject.asObservable()

  /**
   * Observable of the loading state
   */
  public readonly loading$: Observable<boolean> =
    this.loadingSubject.asObservable()

  constructor() {
    if (isPlatformBrowser(this.platformId)) {
      this.initializeSession()
    } else {
      this.loadingSubject.next(false)
    }
  }

  /**
   * Initialize session on browser platform
   */
  private initializeSession(): void {
    this.getSession().subscribe({
      next: (session) => {
        this.sessionSubject.next(session)
        this.loadingSubject.next(false)
      },
      error: (error) => {
        console.error("Failed to initialize session:", error)
        this.sessionSubject.next(null)
        this.loadingSubject.next(false)
      },
    })
  }

  /**
   * Get the current session from the server
   */
  private getSession(): Observable<Session | null> {
    if (!isPlatformBrowser(this.platformId)) {
      return of(null)
    }

    return from(
      fetch(`${this.basePath}/session`, {
        credentials: "include",
      })
    ).pipe(
      switchMap((response) => {
        if (!response.ok) {
          throw new Error(`Session fetch failed: ${response.status}`)
        }
        return from(response.json())
      }),
      catchError((error) => {
        console.error("Session fetch error:", error)
        return of(null)
      })
    )
  }

  /**
   * Refresh the current session
   */
  refreshSession(): Observable<Session | null> {
    this.loadingSubject.next(true)

    return this.getSession().pipe(
      tap((session) => {
        this.sessionSubject.next(session)
        this.loadingSubject.next(false)
      }),
      catchError((error) => {
        console.error("Failed to refresh session:", error)
        this.sessionSubject.next(null)
        this.loadingSubject.next(false)
        return of(null)
      })
    )
  }

  /**
   * Sign in with a provider
   */
  async signIn(
    provider?: ProviderId,
    options?: SignInOptions<true>,
    authorizationParams?: Record<string, string>
  ): Promise<void>
  async signIn(
    provider?: ProviderId,
    options?: SignInOptions<false>,
    authorizationParams?: Record<string, string>
  ): Promise<SignInResponse>
  async signIn<Redirect extends boolean = true>(
    provider?: ProviderId,
    options?: SignInOptions<Redirect>,
    authorizationParams?: Record<string, string>
  ): Promise<SignInResponse | void> {
    if (!isPlatformBrowser(this.platformId)) {
      throw new Error("signIn can only be called in the browser")
    }

    const {
      redirectTo = window.location.href,
      redirect = true,
      ...signInParams
    } = options ?? {}
    const isCredentials = provider === "credentials"

    const signInUrl = `${this.basePath}/${isCredentials ? "callback" : "signin"}${
      provider ? `/${provider}` : ""
    }`

    // Get CSRF token
    const csrfResponse = await fetch(`${this.basePath}/csrf`)
    const { csrfToken } = await csrfResponse.json()

    const params = new URLSearchParams({
      ...signInParams,
      csrfToken,
      callbackUrl: redirectTo,
      ...authorizationParams,
    })

    const response = await fetch(
      `${signInUrl}?${new URLSearchParams(authorizationParams)}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-Auth-Return-Redirect": "1",
        },
        body: params,
        credentials: "include",
      }
    )

    const data = await response.json()

    if (redirect) {
      const url = data.url ?? redirectTo
      window.location.href = url
      if (url.includes("#")) window.location.reload()
      return
    }

    const error = new URL(data.url).searchParams.get("error") ?? undefined
    const code = new URL(data.url).searchParams.get("code") ?? undefined

    return {
      error,
      code,
      status: response.status,
      ok: response.ok,
      url: error ? null : data.url,
    }
  }

  /**
   * Sign out the current user
   */
  async signOut(options?: SignOutOptions): Promise<void> {
    if (!isPlatformBrowser(this.platformId)) {
      throw new Error("signOut can only be called in the browser")
    }

    const { redirectTo = window.location.href, redirect = true } = options ?? {}

    // Get CSRF token
    const csrfResponse = await fetch(`${this.basePath}/csrf`)
    const { csrfToken } = await csrfResponse.json()

    const response = await fetch(`${this.basePath}/signout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Auth-Return-Redirect": "1",
      },
      body: new URLSearchParams({
        csrfToken,
        callbackUrl: redirectTo,
      }),
      credentials: "include",
    })

    const data = await response.json()

    // Update session state immediately
    this.sessionSubject.next(null)

    if (redirect) {
      const url = data.url ?? redirectTo
      window.location.href = url
      if (url.includes("#")) window.location.reload()
    }
  }

  /**
   * Get the current session (synchronous)
   */
  getCurrentSession(): Session | null {
    return this.sessionSubject.value
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return !!this.sessionSubject.value?.user
  }

  /**
   * Get the current user
   */
  getCurrentUser(): User | undefined {
    return this.sessionSubject.value?.user
  }
}

/**
 * Provider function for Angular DI
 */
export function provideAngularAuth(config: AngularAuthConfig) {
  return {
    provide: ANGULAR_AUTH_CONFIG,
    useValue: config,
  }
}

/**
 * Legacy function name for compatibility
 * @deprecated Use AuthService instead
 */
export function AngularAuth() {
  throw new Error(
    "AngularAuth() is deprecated. Use AuthService with provideAngularAuth() instead."
  )
}
