/** Fetch wrapper. Same origin in dev (Vite proxy) and in prod (FastAPI). */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type Query = Record<string, string | number | boolean | undefined | null>;

function url(path: string, query?: Query): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null) search.set(key, String(value));
  }
  const suffix = search.toString();
  return `/api${path}${suffix ? `?${suffix}` : ""}`;
}

async function request<T>(method: string, path: string, options: {
  query?: Query;
  body?: unknown;
} = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url(path, options.query), {
      method,
      headers: {
        Accept: "application/json",
        ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });
  } catch {
    // A stopped backend is the likeliest local failure, and the browser reports
    // it as an opaque TypeError. Say the useful thing instead.
    throw new ApiError(0, "Cannot reach the analyzer — is the server still running?");
  }

  if (!response.ok) throw new ApiError(response.status, await errorDetail(response));
  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return (await response.text()) as unknown as T;
  }
  return (await response.json()) as T;
}

async function errorDetail(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body?.detail === "string") return body.detail;
    if (Array.isArray(body?.detail)) {
      // FastAPI validation errors arrive as a list of {loc, msg}.
      return body.detail.map((d: { msg?: string }) => d.msg ?? "invalid").join("; ");
    }
  } catch {
    /* fall through */
  }
  return `${response.status} ${response.statusText}`;
}

export const api = {
  get: <T>(path: string, query?: Query) => request<T>("GET", path, { query }),
  post: <T>(path: string, body?: unknown, query?: Query) =>
    request<T>("POST", path, { body: body ?? {}, query }),
  put: <T>(path: string, body?: unknown, query?: Query) =>
    request<T>("PUT", path, { body: body ?? {}, query }),
  delete: <T>(path: string, query?: Query) => request<T>("DELETE", path, { query }),
};

/** Absolute URL for an iframe or a link — not fetched through `request`. */
export function apiUrl(path: string, query?: Query): string {
  return url(path, query);
}
