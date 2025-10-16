import { CanActivate, ExecutionContext, Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthService } from '../../auth/auth.service';
import { ROLES_KEY } from './roles.decorator';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private readonly authService: AuthService,
        private reflector: Reflector,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        try {
        const roles = this.reflector.get<string[]>(
            ROLES_KEY,
            context.getHandler(),
        );

        const request = context.switchToHttp().getRequest();
        const { authorization } = request.headers;

        if (!authorization || authorization.trim() === '') {
            throw new UnauthorizedException('Please provide token');
        }

        const authToken = authorization.replace(/bearer/gim, '').trim();
        const user = await this.authService.validateToken(authToken);

        request.user = user;

        if (roles && (!user.role || !roles.includes(user.role))) {
            throw new ForbiddenException(
            'Access denied: You do not have the required permissions',
            );
        }

        return true;
        } catch (error: any) {
        throw new UnauthorizedException(
            error.message || 'Invalid token or session expired! Please sign in',
        );
        }
    }
}