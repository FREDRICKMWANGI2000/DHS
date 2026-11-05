import { Response } from "express";

export interface ApiSuccessEnvelope<T> {
  status: "ok";
  data: T;
}

export interface ApiErrorEnvelope {
  status: "error";
  code: string;
  message: string;
  error: {
    code: string;
    message: string;
  };
}

/**
 * Sends a standardized JSON success response envelope.
 */
export function sendSuccess<T>(
  res: Response,
  statusCode: number,
  data: T
): void {
  const payload: ApiSuccessEnvelope<T> = {
    status: "ok",
    data,
  };
  res.status(statusCode).json(payload);
}

/**
 * Sends a standardized JSON error response envelope containing `error: { code, message }`
 * (as well as top-level `code` and `message` for compatibility).
 */
export function sendError(
  res: Response,
  statusCode: number,
  code: string,
  message: string
): void {
  const payload: ApiErrorEnvelope = {
    status: "error",
    code,
    message,
    error: {
      code,
      message,
    },
  };
  res.status(statusCode).json(payload);
}
