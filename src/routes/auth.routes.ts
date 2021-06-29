import { Router } from 'express';

import * as authCtlr from '../controllers/auth.controller';
import { authorize } from '../middlewares/authorize';

const router = Router();

router.post('/sign-up', authCtlr.signUp);
router.post('/verify-email', authCtlr.verifyEmail);
router.post('/sign-in', authCtlr.signIn);
router.post('/forgot-password', authCtlr.forgotPassword);
router.post('/validate-reset-token', authCtlr.validateResetToken);
router.post('/reset-password', authCtlr.resetPassword);
router.post('/refresh-token', authCtlr.refreshToken);
router.post('/revoke-token', authorize, authCtlr.revokeToken);

export default router;