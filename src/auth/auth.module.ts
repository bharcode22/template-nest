import { PrismaService } from './../../prisma/prisma.service';
import { PrismaModule } from './../../prisma/prisma.module';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { OAuth2Client } from 'google-auth-library';
import * as dotenv from 'dotenv';
dotenv.config();

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    PrismaModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>(process.env.JWT_SECRET),
        signOptions: { expiresIn: '1d' },
      }),
    }),
    ConfigModule
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    {
      provide: OAuth2Client,
      useFactory: (config: ConfigService) => {
        return new OAuth2Client(config.get<string>(process.env.GOOGLE_CLIENT_ID));
      },
      inject: [ConfigService],
    }
  ],
  exports: [AuthService],
})
export class AuthModule {}