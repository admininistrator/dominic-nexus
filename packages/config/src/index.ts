export interface AppConfig {
  appName: string;
  environment: string;
  logLevel: "debug" | "info" | "warn" | "error";
}

const LOG_LEVELS = new Set<AppConfig["logLevel"]>(["debug", "info", "warn", "error"]);

function readLogLevel(value: string | undefined): AppConfig["logLevel"] {
  if (value !== undefined && LOG_LEVELS.has(value as AppConfig["logLevel"])) {
    return value as AppConfig["logLevel"];
  }

  return "info";
}

export function loadConfig(): AppConfig {
  return {
    appName: process.env.DOMINIC_NEXUS_APP_NAME ?? "Dominic Nexus",
    environment: process.env.NODE_ENV ?? "development",
    logLevel: readLogLevel(process.env.DOMINIC_NEXUS_LOG_LEVEL)
  };
}
