import { useEffect, useState } from 'react';
import { fetchTasks, deleteTask } from '@/services/taskService';
import TaskItem from '@/components/TaskItem';
import { Task } from '@/types/task';

export default function Home() {
  const [tasks, setTasks] = useState<Task[]>([]);

  useEffect(() => {
    fetchTasks().then(setTasks);
  }, []);

  const handleDelete = async (id: string) => {
    await deleteTask(id);
    setTasks(tasks.filter(task => task.id !== id));
  };

  return (
    <div className="max-w-2xl mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">Todo List</h1>
      {tasks.map(task => (
        <TaskItem key={task.id} task={task} onUpdate={() => {}} onDelete={handleDelete} />
      ))}
    </div>
  );
}
