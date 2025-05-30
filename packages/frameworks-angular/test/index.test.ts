import { TestBed } from "@angular/core/testing"
import { vi, describe, expect, it, beforeEach } from "vitest"
import { AuthService, ANGULAR_AUTH_CONFIG, provideAngularAuth } from "../src"
import { of } from "rxjs"

// Mock fetch globally
global.fetch = vi.fn()

const mockAuthConfig = {
  providers: [],
  secret: "test-secret",
  trustHost: true,
}

describe("AuthService", () => {
  describe("Service instantiation", () => {
    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [provideAngularAuth(mockAuthConfig), AuthService],
      })
    })

    it("should be created", () => {
      const service = TestBed.inject(AuthService)
      expect(service).toBeTruthy()
    })

    it("should have session$ observable", () => {
      const service = TestBed.inject(AuthService)
      expect(service.session$).toBeDefined()
    })

    it("should have loading$ observable", () => {
      const service = TestBed.inject(AuthService)
      expect(service.loading$).toBeDefined()
    })

    it("should initially return null for getCurrentSession", () => {
      const service = TestBed.inject(AuthService)
      expect(service.getCurrentSession()).toBeNull()
    })

    it("should return false for isAuthenticated initially", () => {
      const service = TestBed.inject(AuthService)
      expect(service.isAuthenticated()).toBe(false)
    })

    it("should return undefined for getCurrentUser initially", () => {
      const service = TestBed.inject(AuthService)
      expect(service.getCurrentUser()).toBeUndefined()
    })
  })

  describe("Provider configuration", () => {
    it("should provide correct configuration", () => {
      const provider = provideAngularAuth(mockAuthConfig)
      expect(provider.provide).toBe(ANGULAR_AUTH_CONFIG)
      expect(provider.useValue).toEqual(mockAuthConfig)
    })
  })

  describe("Session management", () => {
    let service: AuthService

    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [provideAngularAuth(mockAuthConfig), AuthService],
      })
      service = TestBed.inject(AuthService)
    })

    it("should update session state when refreshed", (done) => {
      const mockSession = {
        user: { id: "1", name: "Test User", email: "test@example.com" },
        expires: new Date(Date.now() + 3600000).toISOString(),
      }

      // Mock successful fetch
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockSession),
      } as Response)

      service.refreshSession().subscribe((session) => {
        expect(session).toEqual(mockSession)
        expect(service.getCurrentSession()).toEqual(mockSession)
        expect(service.isAuthenticated()).toBe(true)
        expect(service.getCurrentUser()).toEqual(mockSession.user)
        done()
      })
    })

    it("should handle session fetch errors gracefully", (done) => {
      // Mock failed fetch
      vi.mocked(fetch).mockRejectedValueOnce(new Error("Network error"))

      service.refreshSession().subscribe((session) => {
        expect(session).toBeNull()
        expect(service.getCurrentSession()).toBeNull()
        expect(service.isAuthenticated()).toBe(false)
        done()
      })
    })
  })

  describe("Error handling", () => {
    it("should throw error for deprecated AngularAuth function", () => {
      expect(() => {
        // This should be imported and called, but we'll just test the function
        const { AngularAuth } = require("../src")
        AngularAuth()
      }).toThrow(
        "AngularAuth() is deprecated. Use AuthService with provideAngularAuth() instead."
      )
    })
  })
})

describe("Integration test", () => {
  it("should work with Angular DI system", () => {
    TestBed.configureTestingModule({
      providers: [
        provideAngularAuth({
          providers: [],
          secret: "test-secret",
        }),
      ],
    })

    const config = TestBed.inject(ANGULAR_AUTH_CONFIG)
    expect(config).toBeDefined()
    expect(config.secret).toBe("test-secret")
  })
})
