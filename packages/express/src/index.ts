import { Auth } from "@auth/core"
import { Cookie, parseString, splitCookiesString } from "set-cookie-parser"
import { serialize } from "cookie"
import * as Express from "express"
import type { AuthAction, AuthConfig, Session } from "@auth/core/types"

const DEFAULT_PREFIX = "/auth"

export interface ExpressAuthConfig extends AuthConfig {
  /**
   * Defines the base path for the auth routes.
   * @default '/auth'
   */
  prefix?: string
}

const actions: AuthAction[] = [
  "providers",
  "session",
  "csrf",
  "signin",
  "signout",
  "callback",
  "verify-request",
  "error",
]

// currently multiple cookies are not supported, so we keep the next-auth.pkce.code_verifier cookie for now:
// because it gets updated anyways
// src: https://github.com/solidjs/solid-start/issues/293
const getSetCookieCallback = (cook?: string | null): Cookie | undefined => {
  if (!cook) return
  const splitCookie = splitCookiesString(cook)
  for (const cookName of [
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
    "next-auth.pkce.code_verifier",
    "__Secure-next-auth.pkce.code_verifier",
  ]) {
    const temp = splitCookie.find((e) => e.startsWith(`${cookName}=`))
    if (temp) {
      return parseString(temp)
    }
  }
  return parseString(splitCookie?.[0] ?? "") // just return the first cookie if no session token is found
}

function ExpressAuthHandler(prefix: string, authOptions: ExpressAuthConfig) {
  return async (event: any) => {
    const { request } = event
    console.log(request.url, request)
    const url = new URL(request.url)
    const action = url.pathname
      .slice(prefix.length + 1)
      .split("/")[0] as AuthAction

    if (!actions.includes(action) || !url.pathname.startsWith(prefix + "/")) {
      return
    }

    const res = await Auth(request, authOptions)
    if (["callback", "signin", "signout"].includes(action)) {
      const parsedCookie = getSetCookieCallback(
        res.clone().headers.get("Set-Cookie")
      )
      if (parsedCookie) {
        res.headers.set(
          "Set-Cookie",
          serialize(parsedCookie.name, parsedCookie.value, parsedCookie as any)
        )
      }
    }
    return res
  }
}

export function ExpressAuth(config: ExpressAuthConfig) {
  const { prefix = DEFAULT_PREFIX, ...authOptions } = config
  authOptions.secret ??= "secret" //process.env.AUTH_SECRET
  authOptions.trustHost ??= !!(
    process.env.AUTH_TRUST_HOST ??
    process.env.VERCEL ??
    process.env.NODE_ENV !== "production"
  )
  const handler = ExpressAuthHandler(prefix, authOptions)

  return async (req: any, res: Express.Response) => {
    let headers = new Headers()
    Object.keys(req.headers).forEach((key) => {
      headers.append(key, req.headers[key] as string)
    })
    let request = new Request(`http://localhost:5000/auth${req.url}`, {
      method: req.method,
      body: req.body,
      headers,
    })

    return await handler({ request })
  }
}

export type GetSessionResult = Promise<Session | null>

export async function getSession(
  req: Request,
  options: ExpressAuthConfig
): GetSessionResult {
  const { prefix = DEFAULT_PREFIX, ...authOptions } = options
  authOptions.secret ??= process.env.AUTH_SECRET
  authOptions.trustHost ??= true

  const url = new URL(prefix, req.url)
  const response = await Auth(
    new Request(url, { headers: req.headers }),
    authOptions
  )

  const { status = 200 } = response

  const data = await response.json()

  if (!data || !Object.keys(data).length) return null
  if (status === 200) return data
  throw new Error(data.message)
}
