import { model, Schema, Document } from 'mongoose';
import { Role } from '../enums';

export interface IUserModel extends Document {
  email: string;
  salt: string;
  password: string;
  firstName: string;
  lastName: string;
  acceptTerms: boolean;
  role: Role;
  verificationToken: string | undefined;
  verified: Date;
  resetToken: { token: string, expires: Date } | undefined;
  passwordReset: Date;
  isVerified: boolean;
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
    salt: { type: String, required: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    acceptTerms: Boolean,
    role: { type: String, required: true },
    verificationToken: String,
    verified: Date,
    resetToken: {
      token: String,
      expires: Date,
    },
    passwordReset: Date,
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

// eslint-disable-next-line func-names
userSchema.virtual('isVerified').get(function (this: { verified: string, passwordReset: string }) {
  return !!(this.verified || this.passwordReset);
});

// userSchema.methods.encryptPassword = async (password: string) => {
//   const salt = await bcrypt.genSalt(10);
//   return await bcrypt.hash(password, salt);
// };

// userSchema.methods.comparePassword = async (password: string, receivedPassword: string) => {
//   return await bcrypt.compare(password, receivedPassword);
// };

export default model<IUserModel>('user', userSchema);
