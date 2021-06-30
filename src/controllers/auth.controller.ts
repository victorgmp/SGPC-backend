import { Request, Response } from 'express';
import { IUser } from '../interfaces';

import { IUserModel } from '../models/user.model';
import * as userService from '../services/auth.services';

// helper functions
const setTokenCookie = (res: Response, token: string) => {
  // create cookie with refresh token that expires in 7 days
  const cookieOptions = {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  };
  res.cookie('refreshToken', token, cookieOptions);
};

export const verifyEmail = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    if (!req.body.token) {
      return res.status(400).json({ status: false, message: 'No token received' });
    }

    await userService.verifyEmail(req.body.token);
    return res.status(200).json({ status: true, message: 'Verification successful, you can now login' });
  } catch (error) {
    switch (error.message) {
      case 'EmailVerificationError':
        return res.status(400).send('Verification failed');
      default:
        return res.status(500).send('Internal Server Error');
    }
  }
};

export const signUp = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    const {
      email, firstName, lastName, password, acceptTerms,
    }: IUserModel = req.body;
    if (
      !email
      || !firstName
      || !lastName
      || !password
      || !acceptTerms
    ) {
      return res.status(400).json({ status: false, message: 'Please send your data' });
    }

    const user: IUserModel = req.body;
    await userService.signUp(user, req.get('origin'));

    return res.status(201).send({ status: true, message: 'Registration successful, please check your email for verification instructions' });
  } catch (error) {
    switch (error.message) {
      case 'SignUpError':
        return res.status(400).json({ status: false, message: 'Registration failed' });
      default:
        return res.status(500).send('Internal Server Error');
    }
  }
};

export const signIn = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    const { email, password }: IUserModel = req.body;
    const ipAddress = req.ip;

    if (!email || !password) {
      return res.status(400).json({ status: false, message: 'Please send your data' });
    }
    const user: boolean | IUser = await userService.signIn(email, password, ipAddress);
    if (!user) {
      return res.status(400).json({ status: false, message: 'The email or password are wrong' });
    }

    const { refreshToken, ...userData } = user;
    setTokenCookie(res, user.refreshToken);

    return res.status(200).json({ status: true, payload: userData });
  } catch (error) {
    switch (error.message) {
      case 'SignInError':
        return res.status(400).json({ status: false, message: 'Email or password wrong' });
      default:
        return res.status(500).send('Internal Server Error');
    }
  }
};

export const forgotPassword = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    if (!req.body.email) {
      return res.status(400).json({ status: false, message: 'Please send your email' });
    }

    await userService.forgotPassword(req.body.email, req.get('origin'));
    return res.status(200).json({ status: true, message: 'Please check your email for password reset instructions' });
  } catch (error) {
    switch (error.message) {
      case 'ForgotPasswordError':
        return res.status(400).json({ status: false, message: 'Error recovering password' });
      default:
        return res.status(500).send('Internal Server Error');
    }
  }
};

export const resetPassword = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    if (!req.body.token || !req.body.password) {
      return res.status(400).json({ status: false, message: 'Please send your new password' });
    }

    await userService.resetPassword(req.body.token, req.body.password);

    return res.status(200).json({ status: true, message: 'Password reset successful, you can now login' });
  } catch (error) {
    switch (error.message) {
      case 'ResetPasswordError':
        return res.status(400).json({ status: false, message: 'Error resetting password' });
      default:
        return res.status(500).send('Internal Server Error');
    }
  }
};

export const validateResetToken = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    if (!req.body.token) {
      return res.status(400).json({ status: false, message: 'Please send your token' });
    }

    await userService.validateResetToken(req.body.token);
    return res.status(200).json({ status: true, message: 'Token is valid' });
  } catch (error) {
    switch (error.message) {
      case 'ValidateResetTokenError':
        return res.status(400).json({ status: false, message: 'Invalid token' });
      default:
        return res.status(500).send('Internal Server Error');
    }
  }
};

export const refreshToken = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    const token = req.cookies.refreshToken;
    const ipAddress: string = req.ip;

    const user: boolean | IUser = await userService.refreshToken(token, ipAddress);
    if (!user) {
      return res.status(400).json({ status: false, message: 'Invalid token' });
    }

    // eslint-disable-next-line @typescript-eslint/no-shadow
    const { refreshToken, ...userData } = user;
    setTokenCookie(res, user.refreshToken);

    return res.status(200).json({ status: true, payload: userData });
  } catch (error) {
    switch (error.message) {
      case 'RefreshTokenError':
        return res.status(401).send('Unauthorized');
      default:
        return res.status(500).send('Internal Server Error');
    }
  }
};

export const revokeToken = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    // accept token from request body or cookie
    const token = req.body.token || req.cookies.refreshToken;
    const ipAddress = req.ip;

    if (!token) return res.status(400).json({ status: false, message: 'Token is required' });

    // users can revoke their own tokens
    if (!res.locals.ownsToken(token)) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    await userService.revokeToken(token, ipAddress);

    return res.status(200).json({ status: true, message: 'Token revoked' });
  } catch (error) {
    switch (error.message) {
      case 'RevokeTokenError':
        return res.status(401).send('Unauthorized');
      default:
        return res.status(500).send('Internal Server Error');
    }
  }
};
