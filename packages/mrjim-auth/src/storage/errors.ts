export class StorageError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number, message: string) {
    super(message);
    this.name = "StorageError";
    this.code = code;
    this.status = status;
  }
}

export class StorageProgrammingError extends StorageError {
  constructor(message: string) {
    super("invalid_input", 400, message);
    this.name = "StorageProgrammingError";
  }
}

export class StorageApiError extends StorageError {
  constructor(code: string, status: number, message: string) {
    super(code, status, message);
    this.name = "StorageApiError";
  }
}
