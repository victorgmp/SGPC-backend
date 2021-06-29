import {
  Connection, connection, connect, disconnect,
} from 'mongoose';
import config from './config';

let database: Connection;

export const connectDB = async (): Promise<void> => {
  const uri = config.DB.URI;

  if (database) {
    return;
  }

  connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    useCreateIndex: true,
  });

  database = connection;

  database.once('open', async () => {
    console.log('Connected to database');
  });

  database.on('error', () => {
    console.log('Error connecting to databse');
  });
};

export const disconnectDB = async (): Promise<void> => {
  if (!database) {
    return;
  }

  disconnect();
  console.log('Database disconnected');
};
