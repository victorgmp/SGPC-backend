export interface IEmail {
  to: string;
  subject: string;
  html: string;
  from?: string | undefined;
}