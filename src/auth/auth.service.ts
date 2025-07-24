import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';


@Injectable()
export class AuthService {
    async register(createUserDTO : CreateUserDto) {

        // encyrpt the user password here
        // For example, using bcrypt:
        const hashedPassword = await bcrypt.hash(createUserDTO.password, 10);
        createUserDTO.password = hashedPassword; 
     
        // save the user to the database here
        return createUserDTO;
    }
}
