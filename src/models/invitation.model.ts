import { model, Schema, Document } from 'mongoose';

import { IUser } from '../interfaces';
import { InvitationStatus } from '../enums';

export interface IInvitationModel extends Document {
  email: string;
  sentBy: IUser['id'],
  status: InvitationStatus;
  invitationToken: { token: string, expires: Date } | undefined;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema: Schema = new Schema(
  {
    email: {
      type: String,
      unique: true,
      required: true,
      lowercase: true,
      trim: true,
    },
    sentBy: {
      type: Schema.Types.ObjectId,
      ref: 'user',
    },
    status: { type: String, required: true },
    invitationToken: {
      token: String,
      expires: Date,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

export default model<IInvitationModel>('invitation', userSchema);
