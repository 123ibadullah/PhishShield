import { Router, type IRouter } from "express";
import healthRouter from "./health";
import phishingRouter from "./phishing";
import dashboardRouter from "./dashboard";

const router: IRouter = Router();

router.use(healthRouter);
router.use(phishingRouter);
router.use(dashboardRouter);

export default router;
