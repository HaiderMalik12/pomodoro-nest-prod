import {
  Body,
  Controller,
  Post,
  Req,
  UseGuards,
  Get,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDTO } from './dto/login.dto';
import { UsersService } from 'src/users/users.service';
import { AuthGuard } from '@nestjs/passport';
import { TwoFAService } from './2fa.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userServce: UsersService,
    private twoFAService: TwoFAService,
  ) {}

  @Post('register')
  async register(
    @Body() createUserDto: CreateUserDto,
  ): Promise<{ token: string }> {
    const token = await this.authService.register(createUserDto);
    return { token }; // Return the generated JWT token
  }

  @Post('login')
  async login(
    @Body() loginDTO: LoginDTO,
    @Res({ passthrough: true }) res: any,
  ): Promise<{ message: string }> {
    const token = await this.authService.login(loginDTO);
    // return { token }; // Return the generated JWT token
    res.cookie('access_token', token, {
      httpOnly: true,
      sameSite: 'lax', // Use 'lax' for CSRF protection
      secure: process.env.NODE_ENV === 'production', // Set to true in production
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      path: '/', // Cookie path
    });
    return { message: 'Login successful, token set in cookie' };
  }

  @Get('profile')
  @UseGuards(AuthGuard('jwt')) // Use JWT guard to protect this route
  async profile(@Req() req: any): Promise<{ email: string }> {
    const user = await this.userServce.findUserByEmail(req.user.email);
    if (!user) {
      throw new Error('User not found');
    }
    return { email: user.email };
  }

  @Post('logout')
  async logout(
    @Res({ passthrough: true }) res: any,
  ): Promise<{ message: string }> {
    res.clearCookie('access_token'); // Clear the cookie
    return { message: 'Logout successful, cookie cleared' };
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() req: any) {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthCallback(
    @Req() req: any,
    @Res({ passthrough: true }) res: any,
  ): Promise<{ message: string }> {
    const user = req.user; // User information from Google
    const token = await this.authService.socialLogin(user);

    res.cookie('access_token', token, {
      httpOnly: true,
      sameSite: 'lax', // Use 'lax' for CSRF protection
      secure: process.env.NODE_ENV === 'production', // Set to true in production
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      path: '/', // Cookie path
    });
    return res.redirect('http://localhost:3000/dashboard'); // Redirect to your frontend or desired URL
  }

  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth(@Req() req: any) {}

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthCallback(
    @Req() req: any,
    @Res({ passthrough: true }) res: any,
  ): Promise<{ message: string }> {
    const user = req.user; // User information from Google
    const token = await this.authService.socialLogin(user);

    res.cookie('access_token', token, {
      httpOnly: true,
      sameSite: 'lax', // Use 'lax' for CSRF protection
      secure: process.env.NODE_ENV === 'production', // Set to true in production
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      path: '/', // Cookie path
    });
    return res.redirect('http://localhost:3000/dashboard'); // Redirect to your frontend or desired URL
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('2fa/generate')
  async generateTwoFactorAuthSecret(@Req() req: any) {
    const user = req.user;
    const secret = this.twoFAService.generateSecret(user.email);
    await this.userServce.setTwoFASecret(user.id, secret.base32);
    if (!secret.otpauth_url) {
      throw new Error('OTP Auth URL is missing');
    }
    const qrCode = await this.twoFAService.generateQRCode(secret.otpauth_url);
    return { qrCode, secret: secret.base32 };
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('2fa/enable')
  async enableTwoFactorAuth(@Req() req: any, @Body('code') code: string) {
    const user = await this.userServce.findUserByEmail(req.user.email);
    if (!user || !user.twoFactorSecret) {
      throw new UnauthorizedException('2FA not set up for this user');
    }
    const verified = this.twoFAService.verifyCode(user.twoFactorSecret, code);
    if (!verified) {
      throw new UnauthorizedException('Invalid 2FA code');
    }
    await this.userServce.enableTwoFA(user.id);
    return { message: '2FA enabled successfully', success: true };
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('2fa/verify')
  async verifyTwoFactorAuthCode(@Req() req: any, @Body('code') code: string) {
    const user = await this.userServce.findUserByEmail(req.user.email);
    if (!user || !user.twoFactorSecret) {
      throw new UnauthorizedException('2FA not set up for this user');
    }
    const verified = this.twoFAService.verifyCode(user.twoFactorSecret, code);
    if (!verified) {
      throw new UnauthorizedException('Invalid 2FA code');
    }
    return { message: '2FA verification successful', success: true };
  }
}
