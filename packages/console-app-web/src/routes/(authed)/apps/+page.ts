import { listApps } from "#lib/api.js";
import type { PageLoad } from "./$types";

export const load: PageLoad = async ({ fetch, depends }) => {
  depends("app:apps");
  return { apps: await listApps(fetch) };
};
