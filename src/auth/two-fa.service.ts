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

  verifyCode(secret: string, code: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: code,
      window: 1, // Allow a 1-step window (30 seconds before or after)
    });
  }
}
