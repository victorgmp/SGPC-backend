import { Request, Response } from 'express';

import Task, { ITask } from '../models/task.model';

export const createTask = async (req: Request, res: Response) => {
  try {
    const newTask: ITask = new Task(req.body);
    await newTask.save();
    return res.status(201).send({ status: true, message: 'Task created!' });
  } catch (error) {
    return res.status(400).json({ status: false, message: error.message });
  }
};

export const getTasks = async (req: Request, res: Response) => {
  try {
    const tasks = await Task.find();
    return res.status(200).send({ status: true, payload: tasks });
  } catch (error) {
    return res.status(400).json({ status: false, message: error.message });
  }
};

export const getTask = async (req: Request, res: Response) => {
  try {
    const task = await Task.findById(req.params.taskId);
    return res.status(200).send({ status: true, payload: task });
  } catch (error) {
    return res.status(400).json({ status: false, message: error.message });
  }
};

export const updateTask = async (req: Request, res: Response) => {
  try {
    const task: ITask = req.body;
    await Task.findByIdAndUpdate(
      req.params.taskId,
      task,
      {
        new: true,
      },
    );
    return res.status(200).send({ status: true, payload: task });
  } catch (error) {
    return res.status(400).json({ status: false, message: error.message });
  }
};

export const removeTask = async (req: Request, res: Response) => {
  try {
    await Task.findByIdAndDelete(req.params.taskId);
    return res.status(200).send({ status: true, messsage: 'task deleted!' });
  } catch (error) {
    return res.status(400).json({ status: false, message: error.message });
  }
};
