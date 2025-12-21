/**
 * API configuration and base client
 */

// API base URL - defaults to localhost for development
export const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
export const WS_BASE_URL = import.meta.env.VITE_WS_URL || "ws://localhost:8000";

/**
 * Generic fetch wrapper with error handling
 */
export async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(error.detail || `HTTP ${response.status}`);
  }

  return response.json();
}
