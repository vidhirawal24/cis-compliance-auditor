import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center whitespace-nowrap rounded-md text-xs font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 select-none cursor-pointer',
  {
    variants: {
      variant: {
        default: 'bg-sky-600 text-white hover:bg-sky-500 shadow-sm active:bg-sky-700',
        destructive: 'bg-red-600 text-white hover:bg-red-500 shadow-sm active:bg-red-700',
        outline: 'border border-slate-700 bg-transparent hover:bg-slate-800 text-slate-200 active:bg-slate-700',
        secondary: 'bg-slate-800 text-slate-200 hover:bg-slate-700 active:bg-slate-600',
        ghost: 'hover:bg-slate-800 text-slate-300 hover:text-white',
        link: 'text-sky-400 underline-offset-4 hover:underline p-0 h-auto',
      },
      size: {
        default: 'h-8 px-3 py-1.5',
        sm: 'h-7 rounded px-2.5 text-xs',
        lg: 'h-10 rounded-md px-6 text-sm',
        icon: 'h-8 w-8',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <button
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';

