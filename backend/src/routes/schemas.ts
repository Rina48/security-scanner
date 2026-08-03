import { z } from "zod";

export const severityEnum = z.enum(["critical", "high", "medium", "low"]);
