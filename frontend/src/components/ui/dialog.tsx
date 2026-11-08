import type { ComponentPropsWithoutRef, ReactNode } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";
import { IconButton } from "@/components/ui/button";

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogDescription = DialogPrimitive.Description;

export function DialogTitle({ className, ...props }: ComponentPropsWithoutRef<typeof DialogPrimitive.Title>) {
  return <DialogPrimitive.Title className={cn("text-xl font-bold text-content-emphasis", className)} {...props} />;
}

interface DialogContentProps extends ComponentPropsWithoutRef<typeof DialogPrimitive.Content> {
  children: ReactNode;
}

export function DialogContent({ className, children, ...props }: DialogContentProps) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-scrim" />
      <DialogPrimitive.Content
        className={cn(
          "fixed z-50 flex max-h-[90vh] flex-col gap-4 overflow-y-auto bg-surface-100 p-6 shadow-2xl",
          "inset-x-0 bottom-0 rounded-t-xl min-[600px]:inset-x-auto min-[600px]:bottom-auto min-[600px]:left-1/2 min-[600px]:top-1/2 min-[600px]:w-[min(640px,calc(100vw-2rem))] min-[600px]:-translate-x-1/2 min-[600px]:-translate-y-1/2 min-[600px]:rounded-xl",
          className
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close asChild>
          <IconButton aria-label="Close" className="absolute right-4 top-4">
            <X className="size-5" />
          </IconButton>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}
