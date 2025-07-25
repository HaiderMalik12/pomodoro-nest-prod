import { Body, Controller, Post, Req, UseGuards, Get } from '@nestjs/common';
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
        @Body() loginDTO: LoginDTO
    ): Promise<{token :string}> {
        const token =  await this.authService.login(loginDTO);
        return { token }; // Return the generated JWT token
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
}
