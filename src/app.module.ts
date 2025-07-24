import {  Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports : [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        type: 'postgres',
        host: config.get<string>('DB_HOST'),
        port: config.get<number>('DB_PORT'),
        username: config.get<string>('DB_USERNAME'),
        password:config.get<string>('DB_PASSWORD'),
        database:config.get<string>('DB_NAME'),
        // entities: [User],
        synchronize: true, // set to false in production
        Inject: [ConfigService]
      }),
    }),
    AuthModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
