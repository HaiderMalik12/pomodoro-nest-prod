import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto } from 'src/auth/dto/create-user.dto';
import { Repository } from 'typeorm';

@Injectable()
export class UsersService {
    
    constructor(
        @InjectRepository(User) private readonly userRepository: Repository<User>
    ) {}
    
    async createUser(data: CreateUserDto): Promise<User> {
        const newUser = this.userRepository.create(data);
        return await this.userRepository.save(newUser);
    }
    
    // Example method to find a user by email
    async findUserByEmail(email: string): Promise<User | null> {
       return this.userRepository.findOne({ where: { email } });
    }   
}
