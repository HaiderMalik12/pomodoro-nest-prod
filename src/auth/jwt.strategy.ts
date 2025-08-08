import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy} from "@nestjs/passport";
import { Strategy, ExtractJwt } from "passport-jwt";
import * as cookie from 'cookie';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
 constructor(private configService: ConfigService) {
    const jwtSecret = configService.get<string>('JWT_SECRET');
    if(!jwtSecret) {    
       throw new Error('JWT_SECRET is not defined in the configuration');
    }
    super({
        jwtFromRequest: ExtractJwt.fromExtractors([
         (req) => {
            if(!req.headers.cookie) return null;
            // Parse cookies from the request headers
            const cookies = cookie.parse(req.headers.cookie);
            return cookies['access_token'] ?? null;
         }
        ]),
        secretOrKey: jwtSecret,
    })
 }

async validate(payload: any) {
    // Here you can add additional validation logic if needed
    // For example, you can check if the user exists in the database
    // and return the user object or throw an error if not found.
    
    //MAKE DB CALL TO CHECK THE USER EXISTS
    return { id: payload.id, email: payload.email };
 }
 
}