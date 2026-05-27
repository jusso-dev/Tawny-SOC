import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "@/db/schema";

const url = process.env.DATABASE_URL ?? "postgres://tawny_soc:tawny_soc@localhost:5434/tawny_soc";

const client = postgres(url, {
  max: 10,
  idle_timeout: 30,
  prepare: false,
});

export const db = drizzle(client, { schema });
export { schema };
