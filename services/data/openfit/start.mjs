// The pinned Nitro/Bun server closes its listener on SIGTERM/SIGINT, but its
// remaining background handles keep Bun alive until Docker sends SIGKILL.
// Preserve native connection draining, then exit only after that handler settles.
// Remove this adapter when a pinned upstream image passes native lifecycle tests.
await import('/app/.output/server/index.mjs');

for (const signal of ['SIGTERM', 'SIGINT']) {
  const handlers = process.listeners(signal);
  if (handlers.length !== 1 || handlers[0].constructor.name !== 'AsyncFunction') {
    throw new Error('Unexpected OpenFit shutdown interface');
  }
  process.removeListener(signal, handlers[0]);
  process.once(signal, async () => {
    try {
      await handlers[0](signal);
      process.exit(0);
    } catch {
      // Do not log application state or secret-bearing native errors.
      process.exit(1);
    }
  });
}
