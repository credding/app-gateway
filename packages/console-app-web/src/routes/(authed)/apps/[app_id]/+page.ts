import { error } from "@sveltejs/kit";
import { listAccessGrants, listApps, listCatalog, listIdps } from "#lib/api.js";
import type { PageLoad } from "./$types";

export const load: PageLoad = async ({ fetch, depends, params }) => {
  depends("app:apps");
  const grants = listAccessGrants(fetch, { resource_app_id: params.app_id });
  // Grants 404 for apps the user doesn't own; report that as the app missing below.
  grants.catch(() => {});
  const [apps, idps, catalog] = await Promise.all([
    listApps(fetch),
    listIdps(fetch),
    listCatalog(fetch),
  ]);
  const app = apps.find((a) => a.app_id === params.app_id);
  if (!app) {
    error(404, "app not found");
  }
  return { app, idps, catalog, grants: await grants };
};
