import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { UsersService } from 'src/users/users.service';


@Injectable()
export class AuthService {
    constructor(private readonly usersService: UsersService) {}
    async register(createUserDTO : CreateUserDto) {

        // encyrpt the user password here
        // For example, using bcrypt:
        const hashedPassword = await bcrypt.hash(createUserDTO.password, 10);
        createUserDTO.password = hashedPassword; 
     
        return await this.usersService.createUser(createUserDTO);
        
    }
}
