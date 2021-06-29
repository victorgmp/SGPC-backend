import { Router } from 'express';
import {
  createTask, getTasks, getTask, updateTask, removeTask,
} from '../controllers/task.controller';

const router = Router();

router.route('/')
  .post(createTask)
  .get(getTasks);

router.route('/:taskId')
  .get(getTask)
  .put(updateTask)
  .delete(removeTask);

export default router;
