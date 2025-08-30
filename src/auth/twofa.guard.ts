import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';

@Injectable()
export class TwoFaGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();

    //pending_user cookie should be present
    const pendingUser = request.cookies['pending_user'];

    if (pendingUser) {
      request.user = { id: pendingUser, isTwoFAEnabled: true }; // Attach user info to request object
    }
    if (!request.user) {
      throw new UnauthorizedException('No user found');
    }
    if (!request.user.isTwoFAEnabled) {
      throw new UnauthorizedException('2FA is not enabled for this user');
    }
    return true;
  }
}
