import app from './app';
import { connectDB } from './database';

(async function main() {
  await connectDB();

  app.listen(app.get('port'));
  console.log(`Server running & Listening on port ${app.get('port')}`);
}());
