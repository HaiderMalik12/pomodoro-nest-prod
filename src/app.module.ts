import {  Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes the configuration available globally
      envFilePath: '.env', // Path to your .env file
    }),
    TypeOrmModule.forRootAsync({
      imports : [ConfigModule],
      useFactory: async (config: ConfigService) => {
        // console.log('Database configuration:', {
        //   host: config.get<string>('DB_HOST'),
        //   port: config.get<number>('DB_PORT'),
        //   username: config.get<string>('DB_USERNAME'),
        //   database: config.get<string>('DB_DATABASE'),
        // });
        return {
          type: 'postgres',
          host: config.get<string>('DB_HOST'),
          port: +(config.get<number>('DB_PORT') ?? 5432),
          username: config.get<string>('DB_USERNAME'),
          password: config.get<string>('DB_PASSWORD'),
          database: config.get<string>('DB_DATABASE'),
          autoLoadEntities: true,
          synchronize: true, // Set to false in production
        };
      },
      inject: [ConfigService]
    }),
    AuthModule,
    UsersModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
