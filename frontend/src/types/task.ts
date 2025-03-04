export interface Task {
    id: string;
    title: string;
    description?: string;
    completed: boolean;
    priority?: number;
    dueDate?: string;
    createdAt?: string;
    updatedAt?: string;
    status?: 'pending' | 'in_progress' | 'done';
    tags?: string[];
    assignee?: string;
  }
  