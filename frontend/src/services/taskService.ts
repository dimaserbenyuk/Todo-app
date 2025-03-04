import { Task } from '@/types/task';

const API_URL = process.env.NEXT_PUBLIC_API_URL;
const getToken = () => localStorage.getItem('token');

export const fetchTasks = async (): Promise<Task[]> => {
  const response = await fetch(`${API_URL}/tasks`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  return response.json();
};

export const createTask = async (task: Partial<Task>) => {
  const response = await fetch(`${API_URL}/tasks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify(task),
  });
  return response.json();
};

export const updateTask = async (id: string, task: Partial<Task>) => {
  await fetch(`${API_URL}/tasks/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify(task),
  });
};

export const deleteTask = async (id: string) => {
  await fetch(`${API_URL}/tasks/${id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${getToken()}` },
  });
};
