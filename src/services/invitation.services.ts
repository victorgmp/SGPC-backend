import Invitation, { IInvitationModel } from '../models/invitation.model';
import User from '../models/user.model';
import { InvitationStatus } from '../enums';

import { randomTokenString } from './auth.services';
import { sendInvitationEmail } from './email.services';

import { Invitation as Invit } from '../messages';

// eslint-disable-next-line import/prefer-default-export
export const sendInvitation = async (data: IInvitationModel, origin: string | undefined)
: Promise<void> => {
  try {
    const [invitation, user] = await Promise.all([
      Invitation.findOne({ email: data.email }),
      User.findOne({ email: data.email }),
    ]);

    if (user) {
      throw new Error(Invit.ERROR.USER_ALREADY_REGISTERED);
    }

    const newInvitation: IInvitationModel = new Invitation(data);
    let status = InvitationStatus.SENT;
    // invitation expires after 72 hours
    const invitationToken = {
      token: await randomTokenString(),
      expires: new Date(Date.now() + 72 * 60 * 60 * 1000),
    };

    // update the invitation status and resend the email
    if (invitation && invitation.status !== InvitationStatus.ACCEPTED) {
      status = InvitationStatus.FORWARDED;

      invitation.status = status;
      invitation.invitationToken = invitationToken;

      await Promise.all([
        Invitation.findOneAndUpdate(
          { email: data.email },
          {
            status,
            invitationToken,
          },
        ),
        sendInvitationEmail(invitation, origin),
      ]);
      return;
    }

    newInvitation.sentBy = data.sentBy;
    newInvitation.status = status;
    newInvitation.invitationToken = invitationToken;
    // store the invitation and send email
    await Promise.all([
      newInvitation.save(),
      sendInvitationEmail(newInvitation, origin),
    ]);
  } catch (error) {
    console.log('Error sending invitation:', error);
    throw new Error(Invit.ERROR.SEND_INVITATION_ERROR);
  }
};
