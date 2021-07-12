import { Request, Response } from 'express';

import { IUser } from '../interfaces';
import { Auth, Errors } from '../messages';

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
      return res.status(400).json({ status: false, message: Auth.INFO.NO_TOKEN });
    }

    await userService.verifyEmail(req.body.token);
    return res.status(200).json({ status: true, message: Auth.INFO.VERIFICATION_SUCCESSFUL });
  } catch (error) {
    switch (error.message) {
      case Auth.ERROR.EMAIL_VERIFICATION_ERROR:
        return res.status(400).send(Auth.INFO.VERIFICATION_FAILED);
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
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
      return res.status(400).json({ status: false, message: Auth.INFO.SEND_DATA });
    }

    const user: IUserModel = req.body;
    await userService.signUp(user, req.get('origin'));

    return res.status(201).send({ status: true, message: Auth.INFO.REGISTRATION_SUCCESSFUL });
  } catch (error) {
    switch (error.message) {
      case Auth.ERROR.SIGN_UP_ERROR:
        return res.status(400).json({ status: false, message: Auth.INFO.REGISTRATION_FAILED });
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
    }
  }
};

export const signIn = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    const { email, password }: IUserModel = req.body;
    const ipAddress = req.ip;

    if (!email || !password) {
      return res.status(400).json({ status: false, message: Auth.INFO.SEND_DATA });
    }
    const user: boolean | IUser = await userService.signIn(email, password, ipAddress);
    if (!user) {
      return res.status(400).json({ status: false, message: Auth.INFO.EMAIL_PASSWORD_WRONG });
    }

    const { refreshToken, ...userData } = user;
    setTokenCookie(res, user.refreshToken);

    return res.status(200).json({ status: true, payload: userData });
  } catch (error) {
    switch (error.message) {
      case Auth.ERROR.SIGN_IN_ERROR:
        return res.status(400).json({ status: false, message: Auth.INFO.EMAIL_PASSWORD_WRONG });
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
    }
  }
};

export const forgotPassword = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    if (!req.body.email) {
      return res.status(400).json({ status: false, message: Auth.INFO.SEND_EMAIL });
    }

    await userService.forgotPassword(req.body.email, req.get('origin'));
    return res.status(200).json({ status: true, message: Auth.INFO.CHECK_EMAIL });
  } catch (error) {
    switch (error.message) {
      case Auth.ERROR.FORGOT_PASSWORD_ERROR:
        return res.status(400).json({ status: false, message: Auth.INFO.FORGOT_PASSWORD });
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
    }
  }
};

export const resetPassword = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    if (!req.body.token || !req.body.password) {
      return res.status(400).json({ status: false, message: Auth.INFO.SEND_PASSWORD });
    }

    await userService.resetPassword(req.body.token, req.body.password);

    return res.status(200).json({ status: true, message: Auth.INFO.PASSWORD_RESET });
  } catch (error) {
    switch (error.message) {
      case Auth.ERROR.RESET_PASSWORD_ERROR:
        return res.status(400).json({ status: false, message: Auth.INFO.RESET_PASSWORD_ERROR });
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
    }
  }
};

export const validateResetToken = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    if (!req.body.token) {
      return res.status(400).json({ status: false, message: Auth.INFO.SEND_TOKEN });
    }

    await userService.validateResetToken(req.body.token);
    return res.status(200).json({ status: true, message: Auth.INFO.TOKEN_VALID });
  } catch (error) {
    switch (error.message) {
      case Auth.ERROR.VALIDATE_RESET_TOKEN_ERROR:
        return res.status(400).json({ status: false, message: Auth.INFO.INVALID_TOKEN });
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
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
      return res.status(400).json({ status: false, message: Auth.INFO.INVALID_TOKEN });
    }

    // eslint-disable-next-line @typescript-eslint/no-shadow
    const { refreshToken, ...userData } = user;
    setTokenCookie(res, user.refreshToken);

    return res.status(200).json({ status: true, payload: userData });
  } catch (error) {
    switch (error.message) {
      case Auth.ERROR.REFRESH_TOKEN_ERROR:
        return res.status(401).send(Errors.UNAUTHORIZED);
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
    }
  }
};

export const revokeToken = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    // accept token from request body or cookie
    const token = req.body.token || req.cookies.refreshToken;
    const ipAddress = req.ip;

    if (!token) return res.status(400).json({ status: false, message: Auth.INFO.TOKEN_REQUIRED });

    // users can revoke their own tokens
    if (!res.locals.ownsToken(token)) {
      return res.status(401).json({ message: Errors.UNAUTHORIZED });
    }

    await userService.revokeToken(token, ipAddress);

    return res.status(200).json({ status: true, message: Auth.INFO.TOKEN_REVOKED });
  } catch (error) {
    switch (error.message) {
      case Auth.ERROR.REVOKE_TOKEN_ERROR:
        return res.status(401).send(Errors.UNAUTHORIZED);
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
    }
  }
};
