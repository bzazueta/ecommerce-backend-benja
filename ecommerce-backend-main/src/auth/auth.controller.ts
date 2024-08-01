import { Body, Controller, Delete, Param, ParseIntPipe, Post, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { HasRoles } from '../auth/jwt/has-roles';
import { JwtRole } from '../auth/jwt/jwt-role';
import { JwtAuthGuard } from './jwt/jwt-auth.guard';
import { JwtRolesGuard } from './jwt/jwt-roles.guard';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService) {}

    @Post('register') // http://localhost/auth/register -> POST 
    register(@Body() user: RegisterAuthDto) {
        return this.authService.register(user);
    }
    
    
    @Post('login') // http://localhost/auth/login -> POST 
    login(@Body() loginData: LoginAuthDto) {
        console.log('cliente data ',loginData);
        return this.authService.login(loginData);
    }

    @HasRoles(JwtRole.ADMIN, JwtRole.CLIENT)
    @UseGuards(JwtAuthGuard, JwtRolesGuard)
    @Delete(':id') // http:localhost:3000/categories -> PUT
    delete(
        @Param('id', ParseIntPipe) id: number,
    ) {
        return this.authService.delete(id);
    }

}
