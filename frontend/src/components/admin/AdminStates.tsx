import type { ReactNode } from "react";

export function StateMessage({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div role="status" className="flex flex-col items-center gap-2 px-4 py-16 text-center">
      <span className="text-content-muted [&>svg]:size-12">{icon}</span>
      <h2 className="text-xl font-bold text-content-emphasis">{title}</h2>
      {children && <p className="max-w-md text-sm text-content-muted">{children}</p>}
    </div>
  );
}

export function AdminSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading" className="flex flex-col gap-6 pt-6">
      <div className="grid gap-4 md:grid-cols-3">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-28 rounded-lg bg-surface-200 motion-safe:animate-pulse" />
        ))}
      </div>
      <div className="h-10 rounded-md bg-surface-200 motion-safe:animate-pulse" />
      <div className="flex flex-col gap-2">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className="h-16 rounded-md bg-surface-200 motion-safe:animate-pulse" />
        ))}
      </div>
    </div>
  );
}
