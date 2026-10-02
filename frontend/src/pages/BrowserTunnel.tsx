import { BrowserTunnelForm } from "@/components/BrowserTunnelForm";
import { Header } from "@/components/Header";

export function BrowserTunnel() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="sticky top-0 z-20 bg-background/95 px-6 py-5 backdrop-blur supports-backdrop-filter:bg-background/80 sm:px-8 lg:px-10">
        <Header title="BROWSER TUNNEL" showQuickStartLink={false} />
      </div>
      <main className="mx-auto flex min-h-[calc(100vh-7rem)] max-w-4xl items-start justify-center px-4 py-12 sm:px-6">
        <div className="w-full">
          <div className="mx-auto max-w-2xl text-center">
            <p className="text-sm font-semibold uppercase tracking-normal text-primary">
              HTTPS from WebAssembly
            </p>
            <h1 className="mt-2 text-4xl font-extrabold tracking-normal sm:text-5xl">
              Run Portal in this tab
            </h1>
            <p className="mx-auto mt-4 max-w-xl leading-7 text-text-muted">
              The supported browser connector uses the same lease and tenant TLS
              semantics as the native tunnel, with a WebSocket reverse carrier.
            </p>
          </div>
          <BrowserTunnelForm />
        </div>
      </main>
    </div>
  );
}
