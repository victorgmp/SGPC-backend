import { Request, Response } from 'express';

import { Errors, Invitation as Invit } from '../messages';

import { IInvitationModel } from '../models/invitation.model';
import * as invitationService from '../services/invitation.services';

// eslint-disable-next-line import/prefer-default-export
export const sendInvitation = async (req: Request, res: Response)
: Promise<Response<any, Record<string, any>>> => {
  try {
    const { email } = req.body;
    const sendedBy: string = res.locals.userId;

    if (
      !email
      || !sendedBy
    ) {
      return res.status(400).json({ status: false, message: 'Please send the email' });
    }

    const invitation: IInvitationModel = { ...req.body, sendedBy };
    await invitationService.sendInvitation(invitation, req.get('origin'));

    return res.status(201).send({ status: true, message: 'Invitation has been send' });
  } catch (error) {
    console.log(error);
    switch (error.message) {
      case Invit.ERROR.USER_ALREADY_REGISTERED:
        return res.status(400).json({ status: false, message: 'User already registered' });
      case Invit.ERROR.SEND_INVITATION_ERROR:
        return res.status(400).json({ status: false, message: 'Error sending invitation' });
      default:
        return res.status(500).send(Errors.INTERNAL_ERROR);
    }
  }
};
