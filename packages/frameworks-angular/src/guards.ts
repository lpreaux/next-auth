/**
 * Angular Auth Guards and Utilities
 *
 * This file provides common guards and utilities for Angular Auth integration
 */

import { inject } from "@angular/core"
import {
  Router,
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
} from "@angular/router"
import { AuthService } from "./index"
import { map, take, tap } from "rxjs/operators"
import { Observable } from "rxjs"

/**
 * Authentication guard that redirects unauthenticated users to sign-in page
 */
export const authGuard = (redirectUrl = "/auth/signin") => {
  const authService = inject(AuthService)
  const router = inject(Router)

  return authService.session$.pipe(
    take(1),
    map((session) => {
      if (session?.user) {
        return true
      } else {
        router.navigate([redirectUrl])
        return false
      }
    })
  )
}

/**
 * Guest guard that redirects authenticated users away from auth pages
 */
export const guestGuard = (redirectUrl = "/dashboard") => {
  const authService = inject(AuthService)
  const router = inject(Router)

  return authService.session$.pipe(
    take(1),
    map((session) => {
      if (!session?.user) {
        return true
      } else {
        router.navigate([redirectUrl])
        return false
      }
    })
  )
}

/**
 * Role-based guard for protecting routes based on user roles
 */
export const roleGuard = (
  requiredRoles: string[],
  redirectUrl = "/unauthorized"
) => {
  const authService = inject(AuthService)
  const router = inject(Router)

  return authService.session$.pipe(
    take(1),
    map((session) => {
      if (!session?.user) {
        router.navigate(["/auth/signin"])
        return false
      }

      const userRoles = (session.user as any)?.roles || []
      const hasRequiredRole = requiredRoles.some((role) =>
        userRoles.includes(role)
      )

      if (!hasRequiredRole) {
        router.navigate([redirectUrl])
        return false
      }

      return true
    })
  )
}

/**
 * Permission-based guard for fine-grained access control
 */
export const permissionGuard = (
  requiredPermissions: string[],
  redirectUrl = "/unauthorized"
) => {
  const authService = inject(AuthService)
  const router = inject(Router)

  return authService.session$.pipe(
    take(1),
    map((session) => {
      if (!session?.user) {
        router.navigate(["/auth/signin"])
        return false
      }

      const userPermissions = (session.user as any)?.permissions || []
      const hasAllPermissions = requiredPermissions.every((permission) =>
        userPermissions.includes(permission)
      )

      if (!hasAllPermissions) {
        router.navigate([redirectUrl])
        return false
      }

      return true
    })
  )
}

/**
 * Loading guard that shows loading state while checking authentication
 */
export const loadingAwareGuard = (fallbackGuard: () => Observable<boolean>) => {
  const authService = inject(AuthService)

  return authService.loading$.pipe(
    take(1),
    map((loading) => {
      if (loading) {
        // Return true to allow navigation, the component will handle loading state
        return true
      }
      // Delegate to the actual guard logic
      return fallbackGuard()
    })
  )
}

/**
 * Utility function to check if user has specific role
 */
export function hasRole(session: any, role: string): boolean {
  return session?.user?.roles?.includes(role) || false
}

/**
 * Utility function to check if user has specific permission
 */
export function hasPermission(session: any, permission: string): boolean {
  return session?.user?.permissions?.includes(permission) || false
}

/**
 * Utility function to check if user has any of the specified roles
 */
export function hasAnyRole(session: any, roles: string[]): boolean {
  return roles.some((role) => hasRole(session, role))
}

/**
 * Utility function to check if user has all specified roles
 */
export function hasAllRoles(session: any, roles: string[]): boolean {
  return roles.every((role) => hasRole(session, role))
}

/**
 * Utility function to check if user has any of the specified permissions
 */
export function hasAnyPermission(session: any, permissions: string[]): boolean {
  return permissions.some((permission) => hasPermission(session, permission))
}

/**
 * Utility function to check if user has all specified permissions
 */
export function hasAllPermissions(
  session: any,
  permissions: string[]
): boolean {
  return permissions.every((permission) => hasPermission(session, permission))
}

/**
 * Session resolver for providing session data to route components
 */
export const sessionResolver = () => {
  const authService = inject(AuthService)

  return authService.session$.pipe(take(1))
}

/**
 * Auth state resolver for providing complete auth state
 */
export const authStateResolver = () => {
  const authService = inject(AuthService)

  return authService.session$.pipe(
    take(1),
    map((session) => ({
      session,
      isAuthenticated: !!session?.user,
      user: session?.user || null,
      loading: false, // Since we're taking the current state
    }))
  )
}

/**
 * Conditional guard factory for complex authentication logic
 */
export function createConditionalGuard(
  condition: (
    session: any,
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ) => boolean,
  redirectUrl?: string
) {
  return (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => {
    const authService = inject(AuthService)
    const router = inject(Router)

    return authService.session$.pipe(
      take(1),
      tap((session) => {
        if (!condition(session, route, state)) {
          if (redirectUrl) {
            router.navigate([redirectUrl])
          } else {
            // Default redirect logic
            if (!session?.user) {
              router.navigate(["/auth/signin"])
            } else {
              router.navigate(["/unauthorized"])
            }
          }
        }
      }),
      map((session) => condition(session, route, state))
    )
  }
}

/**
 * Higher-order component helper for wrapping components with auth checks
 */
export function withAuth<T>(
  ComponentClass: new (...args: any[]) => T,
  requiredRoles?: string[]
) {
  return class extends ComponentClass {
    private authService = inject(AuthService)

    constructor(...args: any[]) {
      super(...args)

      // Check authentication and roles
      this.authService.session$.pipe(take(1)).subscribe((session) => {
        if (!session?.user) {
          // Handle unauthenticated user
          console.warn("Component requires authentication")
          return
        }

        if (requiredRoles) {
          const userRoles = (session.user as any)?.roles || []
          const hasRequiredRole = requiredRoles.some((role) =>
            userRoles.includes(role)
          )

          if (!hasRequiredRole) {
            console.warn(
              `Component requires one of roles: ${requiredRoles.join(", ")}`
            )
          }
        }
      })
    }
  }
}

/**
 * Token interceptor helper for adding auth tokens to HTTP requests
 */
export function createAuthInterceptor() {
  return {
    intercept: (req: any, next: any) => {
      const authService = inject(AuthService)
      const session = authService.getCurrentSession()

      if (session?.accessToken) {
        const authReq = req.clone({
          headers: req.headers.set(
            "Authorization",
            `Bearer ${session.accessToken}`
          ),
        })
        return next.handle(authReq)
      }

      return next.handle(req)
    },
  }
}

/**
 * Error handler for auth-related HTTP errors
 */
export function handleAuthError(error: any) {
  const authService = inject(AuthService)
  const router = inject(Router)

  if (error.status === 401) {
    // Unauthorized - redirect to sign in
    authService.signOut({ redirect: false }).then(() => {
      router.navigate(["/auth/signin"])
    })
  } else if (error.status === 403) {
    // Forbidden - redirect to unauthorized page
    router.navigate(["/unauthorized"])
  }

  throw error
}
