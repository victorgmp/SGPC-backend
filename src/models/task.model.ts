import { Document, model, Schema } from 'mongoose';
import { IUserModel } from './user.model';

export interface ITask extends Document {
  user: IUserModel['_id'];
  title: string;
  description: string;
}

const taskSchema: Schema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'user' },
    title: String,
    description: { type: String, required: true },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

export default model<ITask>('task', taskSchema);
