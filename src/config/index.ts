import { config } from 'dotenv';

config();

export default {
  JWT_SECRET: process.env.JWT_SECRET || 'somesecrettoken',
  DB: {
    URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/sgpc',
    USER: process.env.MONGODB_USER,
    PASSWORD: process.env.MONGODB_PASSWORD,
  },
  PORT: process.env.PORT || 4000,
  EMAIL_FROM: process.env.EMAIL_FROM || 'info@email.com',
  smtpOptions: {
    host: process.env.SMTP_HOST || 'smtp.ethereal.email',
    port: Number(process.env.SMTP_PORT) || 587,
    auth: {
      user: process.env.SMTP_USER || 'user@ethereal.email',
      pass: process.env.SMTP_PASS || '123456789',
    },
  },
};
