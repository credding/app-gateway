import { error } from "@sveltejs/kit";
import { ApiError, getCatalogApp } from "#lib/api.js";
import type { PageLoad } from "./$types";

export const load: PageLoad = async ({ fetch, depends, params }) => {
  depends("app:catalog");
  try {
    return { app: await getCatalogApp(fetch, params.app_slug) };
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      error(404, "app not found");
    }
    throw err;
  }
};
