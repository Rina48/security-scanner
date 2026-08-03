import { z } from "zod";
import { urlHasUserInfo } from "../utils/secretMasker.js";

export const severityEnum = z.enum(["critical", "high", "medium", "low"]);

export const targetUrlSchema = z.string().url().superRefine((value, context) => {
  if (urlHasUserInfo(value)) {
    context.addIssue({
      code: "custom",
      message: "URL userinfo is not allowed.",
    });
  }
});
