export interface AuthorizeResponse {
  code: string | null;
  state: string | null;
  error: string | null;
  error_description: string | null;
}
