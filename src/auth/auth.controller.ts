import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('register')
    async register(
        @Body() createUserDto: CreateUserDto
    ): Promise<CreateUserDto> {
        return await this.authService.register(createUserDto);
    }
}
