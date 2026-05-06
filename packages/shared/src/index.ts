export type Result<T, E = Error> =
  | {
      ok: true;
      value: T;
    }
  | {
      ok: false;
      error: E;
    };

export type AsyncResult<T, E = Error> = Promise<Result<T, E>>;

export type JsonPrimitive = string | number | boolean | null;

export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | {
      [key: string]: JsonValue;
    };

export type ISODateTimeString = string;

export function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${String(value)}`);
}