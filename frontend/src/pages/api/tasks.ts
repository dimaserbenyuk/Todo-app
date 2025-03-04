import type { NextApiRequest, NextApiResponse } from 'next';
import { fetchTasks, createTask, updateTask, deleteTask } from '@/services/taskService';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    try {
        switch (req.method) {
            case 'GET': {
                const tasks = await fetchTasks();
                return res.status(200).json(tasks);
            }
            case 'POST': {
                const newTask = await createTask(req.body);
                return res.status(201).json(newTask);
            }
            case 'PUT': {
                const { id, ...taskData } = req.body;
                if (!id) return res.status(400).json({ error: 'Task ID is required' });
                await updateTask(id, taskData);
                return res.status(200).json({ message: 'Task updated' });
            }
            case 'DELETE': {
                const { id } = req.body;
                if (!id) return res.status(400).json({ error: 'Task ID is required' });
                await deleteTask(id);
                return res.status(200).json({ message: 'Task deleted' });
            }
            default:
                res.setHeader('Allow', ['GET', 'POST', 'PUT', 'DELETE']);
                return res.status(405).end(`Method ${req.method} Not Allowed`);
        }
    } catch (error) {
        return res.status(500).json({ error: 'Internal Server Error', details: error });
    }
}