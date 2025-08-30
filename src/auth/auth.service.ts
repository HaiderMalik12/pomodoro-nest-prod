import { Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { LoginDTO } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService, // Assuming you have JwtService injected for token generation
  ) {}

  async socialLogin(userData: {
    email: string;
    firstName: string;
    lastName: string;
    provider: string;
  }) {
    let user = await this.usersService.findUserByEmail(userData.email);
    if (!user) {
      user = await this.usersService.createUser({
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName, // Assuming lastName is optional or not provided
        password: '', // Password can be empty for social logins
      });
    }
    return this.jwtService.sign({ id: user.id, email: user.email });
  }

  async register(createUserDTO: CreateUserDto) {
    // encyrpt the user password here
    // For example, using bcrypt:
    const hashedPassword = await bcrypt.hash(createUserDTO.password, 10);
    createUserDTO.password = hashedPassword;

    const user = await this.usersService.createUser(createUserDTO);
    return this.jwtService.sign({ id: user.id, email: user.email }); // Generate JWT token after user creation
  }

  async login(loginDTO: LoginDTO) {
    const user = await this.usersService.findUserByEmail(loginDTO.email);
    // if user does not exist or password is incorrect, throw an error
    if (!user || !(await bcrypt.compare(loginDTO.password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const token = this.jwtService.sign({ id: user.id, email: user.email });
    return { user, token };
  }
}
