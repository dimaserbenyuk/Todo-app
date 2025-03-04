import { Task } from '@/types/task';

interface TaskItemProps {
  task: Task;
  onUpdate: (id: string) => void;
  onDelete: (id: string) => void;
}

export default function TaskItem({ task, onUpdate, onDelete }: TaskItemProps) {
  return (
    <div className="border p-4 rounded flex justify-between items-center">
      <div>
        <h3 className="text-lg font-bold">{task.title}</h3>
        <p className="text-sm text-gray-500">{task.description}</p>
      </div>
      <div>
        <button onClick={() => onUpdate(task.id)} className="bg-blue-500 text-white px-2 py-1 rounded mr-2">
          Edit
        </button>
        <button onClick={() => onDelete(task.id)} className="bg-red-500 text-white px-2 py-1 rounded">
          Delete
        </button>
      </div>
    </div>
  );
}
