import type { AdminState } from "@/hooks/useAdmin";
import { LeaseFilters } from "./LeaseFilters";
import { LeaseList } from "./LeaseList";
import { PolicyCards } from "./PolicyCards";

export function AdminConsole(admin: AdminState) {
  return (
    <div className="flex flex-col gap-6 pb-24 pt-6">
      <h1 className="text-2xl font-bold text-content-emphasis">Admin</h1>
      {admin.error && (
        <p role="alert" className="rounded-md bg-danger/15 px-4 py-3 text-sm font-medium text-danger">
          {admin.error}
        </p>
      )}
      <PolicyCards {...admin} />
      <section className="flex flex-col gap-4">
        <h2 className="text-xl font-bold text-content-emphasis">Leases</h2>
        <LeaseFilters {...admin} />
        <LeaseList {...admin} />
      </section>
    </div>
  );
}
