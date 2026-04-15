import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { TunnelCommandForm } from "@/components/TunnelCommandForm";

export function TunnelCommandModal() {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button
          type="button"
          className="h-10 cursor-pointer rounded-full bg-primary/12 px-4 text-sm font-semibold text-primary shadow-none transition-colors hover:bg-primary/20"
        >
          Add Your Server
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[550px] max-h-[85vh] overflow-y-auto rounded-sm border border-border bg-card p-0 text-card-foreground shadow-[0_24px_64px_rgba(15,23,42,0.16)] dark:border-white/10 dark:bg-[#0b0b0b] dark:text-zinc-100 dark:shadow-[0_28px_80px_rgba(0,0,0,0.5)] [&>button]:right-5 [&>button]:top-5 [&>button]:rounded-md [&>button]:text-text-muted [&>button]:ring-offset-card [&>button]:hover:bg-foreground/5 [&>button]:hover:text-foreground [&>button]:focus:ring-ring/30 [&>button]:data-[state=open]:bg-transparent [&>button]:data-[state=open]:text-text-muted dark:[&>button]:text-zinc-500 dark:[&>button]:ring-offset-[#0b0b0b] dark:[&>button]:hover:bg-white/5 dark:[&>button]:hover:text-zinc-300 dark:[&>button]:focus:ring-white/20 dark:[&>button]:data-[state=open]:text-zinc-500">
        <DialogHeader className="px-6 pt-6 pb-4 text-left">
          <DialogTitle className="flex items-center gap-2 text-[1.05rem] font-semibold tracking-tight text-foreground dark:text-zinc-100">
            <Terminal className="h-4 w-4" />
            Tunnel Setup Command
          </DialogTitle>
          <DialogDescription className="max-w-[34ch] pt-1 text-sm leading-6 text-muted-foreground dark:text-zinc-400">
            Configure your tunnel settings and copy the command to start
            exposing your local server.
          </DialogDescription>
        </DialogHeader>

        <div className="px-6 pb-6">
          <TunnelCommandForm />
        </div>
      </DialogContent>
    </Dialog>
  );
}
