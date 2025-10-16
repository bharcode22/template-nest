import { Controller, Get, Post, Body, Patch, Param, Delete, Res, Req, HttpStatus } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import * as moment from 'moment';
import { RegisDTO } from './dto/register-auth.dto';
import { LoginDTO } from './dto/login-auth.dto';
import { JwtService } from '@nestjs/jwt';

@Controller('auth')
export class AuthController {
    constructor(
        private authService: AuthService, 
        private readonly jwtService: JwtService
    ){}

    @Post('register')
    async register( @Body() body: RegisDTO, @Res() res: Response ) {
        try {
            const newUser = await this.authService.register(body);

            const formatData = {
                username: newUser.username,
                name: newUser.name, 
            }

            return res.status(HttpStatus.CREATED).json({
                message: 'User registered successfully',
                data: formatData,
            });
        } catch (error: any) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
                message: 'Failed to register user',
                error: error.message,
            });
        }
    }

    @Post('login')
    async login( @Body() body: LoginDTO, @Res() res: Response) {
        try {
            const { access_token, user } = await this.authService.login(body);
            return res.status(HttpStatus.OK).json({
                message: 'Login successful',
                data: {
                    user: user,
                    token: access_token
                }
            });
        } catch (error: any) {
            return res.status(HttpStatus.UNAUTHORIZED).json({
                message: 'Login failed',
                error: error.message,
            });
        }
    }

    @Post('logout')
    async logout(@Req() req: Request, @Res() res: Response) {
        try {
            interface CustomHeaders extends Headers {
                authorization?: string;
            }
            const token = (req.headers as CustomHeaders).authorization?.split(' ')[1];
            if (!token) {
                return res.status(HttpStatus.BAD_REQUEST).json({
                    message: 'Token is missing',
                });
            }

            const blacklistData = await this.authService.logout(token)

            const formatLogout = {
                logoutAt : moment(blacklistData.createdAt).format('YYYY-MM-DD'),
            }

            return res.status(HttpStatus.OK).json({
                message: "Logout success", 
                data: formatLogout
            })

        } catch (error: any) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
                message: 'Logout failed',
                error: error.message,
            });
        }
    }

    @Post('google-login')
    async googleLogin(@Body('token') token: string, @Res() res: Response) {
        try {
            const result = await this.authService.verifyGoogleLogin(token);

            return res.status(HttpStatus.OK).json({
                message: 'Google login successful',
                ...result
            });
        } catch (error: any) {
            return res.status(HttpStatus.UNAUTHORIZED).json({
                message: 'Login failed',
                error: error.message,
            });
        }
    }
}