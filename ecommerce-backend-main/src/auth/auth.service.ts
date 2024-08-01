import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../users/user.entity';
import { Repository, In } from 'typeorm';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Rol } from '../roles/rol.entity';
import { existsSync } from 'fs';


@Injectable()
export class AuthService {

    constructor(
        @InjectRepository(User) private usersRepository: Repository<User>,
        @InjectRepository(Rol) private rolesRepository: Repository<Rol>,

        private jwtService: JwtService
    ) {}

    async register(user: RegisterAuthDto) {
        console.log("user",JSON.stringify(user))
        const { email, phone } = user;
        const emailExist = await this.usersRepository.findOneBy({ email: email })

        if (emailExist) {
            // 409 CONFLICT
            throw new HttpException('El email ya esta registrado', HttpStatus.CONFLICT);
        }

        const phoneExist = await this.usersRepository.findOneBy({phone: phone});

        if (phoneExist) {
            throw new HttpException('El telefono ya esta registrado', HttpStatus.CONFLICT)
        }

        const newUser = this.usersRepository.create(user);
        let rolesIds = [];
        
        if (user.rolesIds !== undefined && user.rolesIds !== null) { // DATA
            rolesIds = user.rolesIds;
        }
        else {
            rolesIds.push('CLIENT')
        }
        
        const roles = await this.rolesRepository.findBy({ id: In(rolesIds) });
        newUser.roles = roles;

        const userSaved = await this.usersRepository.save(newUser);

        const rolesString = userSaved.roles.map(rol => rol.id); //['CLIENT', 'ADMIN']
        const payload = { id: userSaved.id, name: userSaved.name, roles: rolesString };
        const token = this.jwtService.sign(payload);
        const data = {
            user: userSaved,
            token: 'Bearer ' + token
        }
        delete data.user.password;
        return data;
    }

    async login(loginData: LoginAuthDto) {
        //console.log(`login data ${loginData.email} ${loginData.password}`);
        const { email, password } = loginData;
        const userFound = await this.usersRepository.findOne({ 
            where: { email: email },
            relations: ['roles']
         })
         console.log(`userFound ${JSON.stringify(userFound)}`);
        if (!userFound) {
            throw new HttpException('El email no existe', HttpStatus.NOT_FOUND);
        }
        // console.log(`password ${password}`);
        // console.log(`userFound.password ${userFound.password}`); 
        const isPasswordValid = await compare(password, userFound.password);
        if (!isPasswordValid) {
            console.log('PASSWORD INCORRECTO');
            
            // 403 FORBITTEN access denied
            throw new HttpException('La contraseña es incorrecta', HttpStatus.FORBIDDEN);
        }

        const rolesIds = userFound.roles.map(rol => rol.id); //['CLIENT', 'ADMIN']

        const payload = { 
            id: userFound.id, 
            name: userFound.name, 
            roles: rolesIds 
        };
        const token = this.jwtService.sign(payload);
        const data = {
            user: userFound,
            token: 'Bearer ' + token
        }

        delete data.user.password;
        console.log('response login data ', data);
        return data;
    }

    async delete(id: number)  {
        const productFound = await this.usersRepository.findOneBy({ id: id });
        if (!productFound) {
            throw new HttpException("Usuario no encontrado", HttpStatus.NOT_FOUND);
        }
        return this.usersRepository.delete(id);
    }

}
