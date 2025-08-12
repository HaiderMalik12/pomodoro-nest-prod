import { Body, Controller, Post, Req, UseGuards, Get, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDTO } from './dto/login.dto';
import { UsersService } from 'src/users/users.service';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
    constructor(
        private authService: AuthService,
        private userServce: UsersService

    ) {}

    @Post('register')
    async register(
        @Body() createUserDto: CreateUserDto
    ): Promise<{token :string}> {
        const token =  await this.authService.register(createUserDto);
        return { token }; // Return the generated JWT token
    }

    @Post('login')
    async login(
        @Body() loginDTO: LoginDTO,
        @Res({passthrough: true}) res: any
    ): Promise<{message :string}> {
        const token =  await this.authService.login(loginDTO);
        // return { token }; // Return the generated JWT token
        res.cookie('access_token', token, {
            httpOnly: true,
            sameSite: 'lax', // Use 'lax' for CSRF protection
            secure: process.env.NODE_ENV === 'production', // Set to true in production
            maxAge: 24 * 60 * 60 * 1000, // 1 day
            path: '/', // Cookie path
        });
        return {message: 'Login successful, token set in cookie'};
    }

    @Get('profile')
    @UseGuards(AuthGuard('jwt')) // Use JWT guard to protect this route
    async profile(
        @Req() req: any
    ): Promise<{email: string}> {
        const user =  await this.userServce.findUserByEmail(req.user.email);
        if (!user) {
            throw new Error('User not found');
        }
        return { email: user.email }; 
    }

    @Post('logout')
    async logout(
        @Res({passthrough: true}) res: any
    ): Promise<{message :string}> {
        res.clearCookie('access_token'); // Clear the cookie
        return {message: 'Logout successful, cookie cleared'};
    }
}
