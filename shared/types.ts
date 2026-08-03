/**
 * Shared domain types — single source of truth.
 * Backend (backend/src/types.ts) keeps the actual definitions.
 * All other consumers (frontend, MCP server, etc.) should import from here.
 */
export type * from "../backend/src/types";
