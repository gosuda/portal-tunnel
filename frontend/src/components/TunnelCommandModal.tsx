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
import type { Lease } from "@/types/api";

export function TunnelCommandModal({ leases }: { leases: Lease[] }) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button
          type="button"
          className="h-10 cursor-pointer rounded-md bg-primary/10 px-4 text-sm font-semibold text-primary shadow-none transition-colors hover:bg-primary/16"
        >
          Add Your Server
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[550px] max-h-[85vh] overflow-y-auto rounded-md border border-border bg-card p-0 text-card-foreground shadow-[0_18px_48px_rgba(15,23,42,0.14)] dark:border-white/10 dark:bg-card dark:text-zinc-100 dark:shadow-[0_22px_56px_rgba(0,0,0,0.42)] [&>button]:right-5 [&>button]:top-5 [&>button]:rounded-md [&>button]:text-text-muted [&>button]:ring-offset-card [&>button]:hover:bg-foreground/5 [&>button]:hover:text-foreground [&>button]:focus:ring-ring/30 [&>button]:data-[state=open]:bg-transparent [&>button]:data-[state=open]:text-text-muted dark:[&>button]:text-zinc-500 dark:[&>button]:ring-offset-card dark:[&>button]:hover:bg-white/5 dark:[&>button]:hover:text-zinc-300 dark:[&>button]:focus:ring-white/20 dark:[&>button]:data-[state=open]:bg-transparent">
        <DialogHeader className="px-6 pt-6 pb-4 text-left">
          <DialogTitle className="flex items-center gap-2 text-[1.05rem] font-semibold tracking-normal text-foreground dark:text-zinc-100">
            <Terminal className="h-4 w-4" />
            Tunnel Setup Command
          </DialogTitle>
          <DialogDescription className="max-w-[34ch] pt-1 text-sm leading-6 text-muted-foreground dark:text-zinc-400">
            Configure your tunnel settings and copy the command to start
            exposing your local server.
          </DialogDescription>
        </DialogHeader>

        <div className="px-6 pb-6">
          <TunnelCommandForm leases={leases} />
        </div>
      </DialogContent>
    </Dialog>
  );
}
