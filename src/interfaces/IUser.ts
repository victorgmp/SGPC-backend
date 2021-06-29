import { Role } from '../enums';

export interface IUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: Role;
  refreshToken: string;
  jwtToken: string;
  createdAt: Date;
  updatedAt: Date;
}
