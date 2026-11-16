/** Runs a mutation, tracking pending state and surfacing API errors as a message. */
export function action() {
  let pending = $state(false);
  let error = $state<string | null>(null);
  return {
    get pending() {
      return pending;
    },
    get error() {
      return error;
    },
    clear() {
      error = null;
    },
    async run<T>(fn: () => Promise<T>): Promise<T | undefined> {
      pending = true;
      error = null;
      try {
        return await fn();
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
        return undefined;
      } finally {
        pending = false;
      }
    },
  };
}
