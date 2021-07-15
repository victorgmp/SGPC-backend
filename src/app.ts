import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

import pkg from '../package.json';
import config from './config';
import taskRoutes from './routes/task.routes';
import authRoutes from './routes/auth.routes';
import invitationRoutes from './routes/invitation.routes';
// import specialRoutes from './routes/special.routes';

const app = express();

// settings
app.set('pkg', pkg);

app.set('port', config.PORT);

// middlewares
app.use(helmet());
app.use(morgan('dev'));
// app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }));
app.use(cors());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.json());

app.get('/', (req, res) => res.json({
  name: app.get('pkg').name,
  author: app.get('pkg').author,
  description: app.get('pkg').description,
  version: app.get('pkg').version,
}));

app.use('/api/auth', authRoutes);
app.use('/api/task', taskRoutes);
app.use('/api/invitation', invitationRoutes);

export default app;
