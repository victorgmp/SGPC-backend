import nodemailer from 'nodemailer';

import config from '../config';
import { IUserModel } from '../models/user.model';
import { IEmail } from '../interfaces';

const sendEmail = async (
  { to, subject, html, from = config.EMAIL_FROM }: IEmail,
  ) => {
  const transporter = nodemailer.createTransport(config.smtpOptions);
  await transporter.sendMail({ from, to, subject, html });
};

export const sendVerificationEmail = async (user: IUserModel, origin: string | undefined) => {
  let message;
  if (origin) {
    const verifyUrl = `${origin}/user/verify-email?token=${user.verificationToken}`;
    message = `<p>Please click the below link to verify your email address:</p>
                 <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
  } else {
    message = `<p>Please use the below token to verify your email address with the <code>/user/verify-email</code> api route:</p>
                 <p><code>${user.verificationToken}</code></p>`;
  }

  await sendEmail({
    to: user.email,
    subject: 'Sign-up Verification API - Verify Email',
    html: `<h4>Verify Email</h4>
             <p>Thanks for registering!</p>
             ${message}`,
  });
};

export const sendAlreadyRegisteredEmail = async (email: string, origin: string | undefined) => {
  let message;
  if (origin) {
    message = `<p>If you don't know your password please visit the <a href="${origin}/user/forgot-password">forgot password</a> page.</p>`;
  } else {
    message = "<p>If you don't know your password you can reset it via the <code>/user/forgot-password</code> api route.</p>";
  }

  await sendEmail({
    to: email,
    subject: 'Sign-up Verification API - Email Already Registered',
    html: `<h4>Email Already Registered</h4>
             <p>Your email <strong>${email}</strong> is already registered.</p>
             ${message}`,
  });
};

export const sendPasswordResetEmail = async (user: IUserModel, origin: string | undefined) => {
  let message;
  if (origin && user.resetToken && user.resetToken.token) {
    const resetUrl = `${origin}/user/reset-password?token=${user.resetToken.token}`;
    message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                 <p><a href="${resetUrl}">${resetUrl}</a></p>`;
  } else if (user.resetToken && user.resetToken.token) {
    message = `<p>Please use the below token to reset your password with the <code>/user/reset-password</code> api route:</p>
                 <p><code>${user.resetToken.token}</code></p>`;
  }

  await sendEmail({
    to: user.email,
    subject: 'Sign-up Verification API - Reset Password',
    html: `<h4>Reset Password Email</h4>
             ${message}`,
  });
};
