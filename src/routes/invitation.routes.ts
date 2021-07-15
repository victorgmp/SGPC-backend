import { Router } from 'express';

import * as invitationCtlr from '../controllers/invitation.controller';
import { authorize } from '../middlewares/authorize';

const router = Router();

router.post('/send-invitation', authorize, invitationCtlr.sendInvitation);

export default router;
