import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

import config from '../config';
import User from '../models/user.model';
import RefreshToken from '../models/refreshToken.model';
import { IToken } from '../interfaces';
// import { Role } from '../enums';

// eslint-disable-next-line import/prefer-default-export
export const authorize = async (req: Request, res: Response, next: NextFunction)
// eslint-disable-next-line consistent-return
: Promise<Response<any, Record<string, any>>> => {
  // const token = <string>req.headers['x-access-token'];
  const authorization = req.get('authorization');
  let token: string;

  if (authorization && authorization.toLowerCase().startsWith('bearer ')) {
    token = authorization.substring(7);
  }

  if (!token) return res.status(403).json({ status: false, message: 'No token provided or malformed' });

  try {
    const jwtPayload = <IToken>jwt.verify(token, config.JWT_SECRET);

    const user = await User.findById(jwtPayload.id, { password: 0 });
    if (!user) return res.status(404).json({ status: false, message: 'No user found' });

    const refreshTokens = await RefreshToken.find({ user: user.id });
    // attach user id to locals response object
    res.locals.userId = jwtPayload.id;
    res.locals.userRole = user.role;
    res.locals.ownsToken = (tok: string) => !!refreshTokens.find((x) => x.token === tok);

    next();
  } catch (error) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
};

// export const isAdmin = async (req: Request, res: Response, next: NextFunction) => {
//   try {
//     const user = await User.findById(res.locals.userId, { password: 0 });
//     if (user && user.role === Role.ADMIN) {
//       next();
//       return;
//     }

//     return res.status(403).json({ message: 'Require Admin Role' });
//   } catch (error) {
//     return res.status(500).send('Internal Server Error');
//   }
// };
