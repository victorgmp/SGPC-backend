/* eslint-disable func-names */
import { model, Schema, Document } from 'mongoose';
import { IUserModel } from './user.model';

export interface IRefreshTokenModel extends Document {
  user: IUserModel['_id'];
  token: string;
  expires: Date;
  created: Date;
  createdByIp: string;
  revoked: Date;
  revokedByIp: string;
  replacedByToken: string;
  isExpired: boolean;
  isActive: boolean;
}

const refreshTokenSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'user' },
    token: String,
    expires: Date,
    created: { type: Date, default: Date.now },
    createdByIp: String,
    revoked: Date,
    revokedByIp: String,
    replacedByToken: String,
  },
  {
    versionKey: false,
  },
);

refreshTokenSchema.virtual('isExpired').get(function (this: { expires: number }) {
  const isExpired: boolean = Date.now() >= this.expires;
  return isExpired;
});

refreshTokenSchema.virtual('isActive').get(function (this: { revoked: Date, isExpired: boolean }) {
  const isActive: boolean = !this.revoked && !this.isExpired;
  return isActive;
});

export default model<IRefreshTokenModel>('refreshToken', refreshTokenSchema);
