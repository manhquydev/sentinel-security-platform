import { service } from "./lib/alias";
export { settings } from "./config";
import "./missing";

const lazy = import("./lazy");
const dynamic = import(moduleName);

router.get("/accounts/:id", requireAuth, service);
router.use("/admin", authMiddleware);

const sessionSecret = process.env.SESSION_SECRET;
const region = config.get("REGION");
