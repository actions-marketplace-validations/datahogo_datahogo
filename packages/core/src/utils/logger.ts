type LogLevel = "info" | "warn" | "error" | "debug";

interface LogContext {
  scanId?: string;
  engine?: string;
  duration?: number;
  [key: string]: unknown;
}

function formatLog(level: LogLevel, message: string, context?: LogContext): string {
  const timestamp = new Date().toISOString();
  const prefix = context?.scanId ? `[scan:${context.scanId}]` : "";
  const enginePrefix = context?.engine ? `[${context.engine}]` : "";
  const extra = context
    ? Object.entries(context)
        .filter(([key]) => key !== "scanId" && key !== "engine")
        .map(([key, value]) => `${key}=${value}`)
        .join(" ")
    : "";

  return `${timestamp} ${level.toUpperCase()} ${prefix}${enginePrefix} ${message}${extra ? " " + extra : ""}`;
}

export function log(message: string, context?: LogContext): void {
  console.log(formatLog("info", message, context));
}

export function warn(message: string, context?: LogContext): void {
  console.warn(formatLog("warn", message, context));
}

export function error(message: string, context?: LogContext): void {
  console.error(formatLog("error", message, context));
}

export function debug(message: string, context?: LogContext): void {
  if (process.env.DEBUG === "true") {
    console.debug(formatLog("debug", message, context));
  }
}
