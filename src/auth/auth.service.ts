import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class AuthService {
    register(createUserDTO : CreateUserDto) {
        return createUserDTO;
    }
}
