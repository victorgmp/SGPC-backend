import { Db, MongoClient } from 'mongodb';
import config from './config';

let db: Db | null = null;

export async function connectDB() {
  if (db) return db;
  const client = await MongoClient.connect(config.DB.URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  db = client.db();
  console.log('Got DB', db);
  return db;
}