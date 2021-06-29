import crypto from 'crypto';
import jwt from 'jsonwebtoken';

import config from '../config';
import User, { IUserModel } from '../models/user.model';
import RefreshToken, { IRefreshTokenModel } from '../models/refreshToken.model';
import Role from '../enums/Role';
import { IUser } from '../interfaces';

import * as emailServices from './email.services';

export const hashPassword = async (salt: string, password: string): Promise<string> => {
  // return bcrypt.hash(password, salt);
  const hash = crypto.createHmac('sha512', salt);
  hash.update(password);

  return hash.digest('hex');
};

const randomTokenString = async (): Promise<string> => crypto.randomBytes(40).toString('hex');

const generateJwtToken = (user: IUserModel)
: string => jwt.sign({ id: user.id, email: user.email }, config.JWT_SECRET, {
  expiresIn: 900,
});

const generateRefreshToken = async (userId: string, ipAddress: string)
: Promise<IRefreshTokenModel> => new RefreshToken({
  user: userId,
  token: await randomTokenString(),
  expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  createdByIp: ipAddress,
});

const getRefreshToken = async (token: string) => {
  const refreshToken: IRefreshTokenModel | null = await RefreshToken.findOne({ token }).populate('user');
  // if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
  if (!refreshToken || !refreshToken.isActive) return false;
  return refreshToken;
};

const toPublic = (user: IUserModel, jwtToken: string, refreshToken: string): IUser => ({
  refreshToken,
  jwtToken,
  id: user.id,
  email: user.email,
  firstName: user.firstName,
  lastName: user.lastName,
  role: user.role,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

export const verifyEmail = async (token: string): Promise<boolean> => {
  try {
    const user = await User.findOne({ verificationToken: token });

    if (!user) return false;

    user.verified = new Date(Date.now());
    user.verificationToken = undefined;
    await user.save();
    return true;
  } catch (error) {
    console.log('Error verifying email:', error);
    throw new Error('EmailVerificationError');
  }
};

export const signUp = async (data: IUserModel, origin: string | undefined): Promise<boolean> => {
  try {
    const user = await User.findOne({ email: data.email });
    if (user) {
      // send already registered error in email to prevent account enumeration
      await emailServices.sendAlreadyRegisteredEmail(data.email, origin);
      return true;
    }

    const newUser: IUserModel = new User(data);
    // first registered user is an admin
    const isFirstAccount: boolean = (await User.countDocuments({})) === 0;
    newUser.role = isFirstAccount ? Role.ADMIN : Role.USER;
    newUser.verificationToken = await randomTokenString();

    newUser.salt = crypto.randomBytes(16)
      .toString('hex')
      .slice(0, 16);
    newUser.password = await hashPassword(newUser.salt, data.password);

    // add a new user
    await newUser.save();
    // send email
    await emailServices.sendVerificationEmail(newUser, origin);
    return true;
  } catch (error) {
    console.log('Error signup user:', error);
    throw new Error('SignUpError');
  }
};

export const signIn = async (email: string, password: string, ipAddress: string)
: Promise<false | IUser> => {
  try {
    const user = await User.findOne({ email });

    if (
      !user
      || !user.isVerified
    ) {
      return false;
      // TODO: return user not verified
    }

    const passwordHash = await hashPassword(user.salt, password);

    if (passwordHash !== user.password) {
      return false;
      // TODO: return email or password wrong
    }
    // const isMatch = user ? await bcrypt.compare(password, user.password) : false;
    // authentication successful so generate jwt and refresh tokens
    const jwtToken: string = generateJwtToken(user);
    const refreshToken = await generateRefreshToken(user.id, ipAddress);
    // save refresh token
    const newRefreshToken: IRefreshTokenModel = new RefreshToken(refreshToken);
    await newRefreshToken.save();

    return {
      ...toPublic(user, jwtToken, newRefreshToken.token),
    };
  } catch (error) {
    console.log('Error signin user:', error);
    throw new Error('SignInError');
  }
};

export const forgotPassword = async (email: string, origin: string | undefined)
: Promise<boolean> => {
  try {
    const user = await User.findOne({ email });
    // always return ok response to prevent email enumeration
    if (!user) return true;

    // create reset token that expires after 24 hours
    user.resetToken = {
      token: await randomTokenString(),
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    };
    await user.save();

    // send email
    await emailServices.sendPasswordResetEmail(user, origin);
    return true;
  } catch (error) {
    console.log('Error recovering password: ', error);
    throw new Error('ForgotPasswordError');
  }
};

export const resetPassword = async (token: string, password: string): Promise<boolean> => {
  try {
    const user = await User.findOne({
      'resetToken.token': token,
      'resetToken.expires': { $gt: Date.now() },
    });

    if (!user) return false;

    // update password and remove reset token
    user.password = await hashPassword(user.salt, password);
    user.passwordReset = new Date(Date.now());
    user.resetToken = undefined;
    await user.save();
    return true;
  } catch (error) {
    console.log('Error resetting password: ', error);
    throw new Error('ResetPasswordError');
  }
};

export const validateResetToken = async (token: string): Promise<boolean> => {
  try {
    const user = await User.findOne({
      'resetToken.token': token,
      'resetToken.expires': { $gt: Date.now() },
    });

    if (user) return true;
    return false;
  } catch (error) {
    console.log('Error validating reset token: ', error);
    throw new Error('ValidateResetTokenError');
  }
};

export const refreshToken = async (token: string, ipAddress: string): Promise<false | IUser> => {
  try {
    const oldRefreshToken = await getRefreshToken(token);
    if (!oldRefreshToken) return false;

    const { user } = oldRefreshToken;

    // replace old refresh token with a new one and save
    const newRefreshToken = await generateRefreshToken(user, ipAddress);

    // const replacedRefreshToken: IRefreshTokenModel = new RefreshToken({
    //   revoked: new Date(Date.now()),
    //   revokedByIp: ipAddress,
    //   replacedByToken: newRefreshToken.token,
    //   ...oldRefreshToken,
    // });
    // console.log('replacedRefreshToken', replacedRefreshToken);
    oldRefreshToken.revoked = new Date(Date.now());
    oldRefreshToken.revokedByIp = ipAddress;
    oldRefreshToken.replacedByToken = newRefreshToken.token;
    await oldRefreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken: string = generateJwtToken(user);

    // return basic details and tokens
    return {
      ...toPublic(user, jwtToken, newRefreshToken.token),
    };
  } catch (error) {
    console.log('Error refreshing token: ', error);
    throw new Error('RefreshTokenError');
  }
};

export const revokeToken = async (token: string, ipAddress: string): Promise<boolean> => {
  try {
    const oldRefreshToken = await getRefreshToken(token);
    if (!oldRefreshToken) return false;

    // revoke token and save
    oldRefreshToken.revoked = new Date(Date.now());
    oldRefreshToken.revokedByIp = ipAddress;
    await oldRefreshToken.save();
    return true;
  } catch (error) {
    console.log('Error revoking token: ', error);
    throw new Error('RevokeTokenError');
  }
};
