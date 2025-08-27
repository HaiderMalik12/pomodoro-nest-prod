import { Injectable } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';

@Injectable()
export class TwoFAService {
  generateSecret(email: string) {
    const secret = speakeasy.generateSecret({
      name: `PomodoroApp (${email})`,
    });
    return secret;
  }
  generateQRCode(otpauthUrl: string) {
    return qrcode.toDataURL(otpauthUrl);
  }
}
