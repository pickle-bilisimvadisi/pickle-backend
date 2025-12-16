import { ConflictException, Injectable, InternalServerErrorException, NotFoundException, BadRequestException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as crypto from 'crypto';
import { Role } from '@prisma/client';

interface User {
    id: string;
    email: string;
    password: string;
    role: string;
}

@Injectable()
export class UserService {
    constructor (private readonly prismaService: PrismaService) {}

    async findAll(userId: string) {
        void(userId)
        const users = await this.prismaService.user.findMany();
        if (users.length === 0) {
            throw new NotFoundException('No users found');
        }
        return users.map((user: User) => ({
            id: user.id,
            email: user.email,
        }));
    }
    
    async getUser(userId: string) {
        const user = await this.prismaService.user.findUnique({
            where: { id: userId },
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        return {
            email: user.email,
            role: user.role
        };
    }

    async findById(id: string) {
        const user = await this.prismaService.user.findUnique({
            where: { id },
        });

        if (!user) {
            throw new NotFoundException('User not found');
        }
        return {
            id: user.id,
            email: user.email,
            password: user.password,
            role: user.role
        };
    }
    
    async findByEmail(email: string) {
        const user = await this.prismaService.user.findUnique({
            where: { email },
        });

        return user;
    }

    async createUser(createUserDto: CreateUserDto) {
        const userExists = await this.prismaService.user.findUnique({
            where: { email: createUserDto.email },
        });

        if (userExists) {
            throw new ConflictException('User already exists');
        }
        
        const newUser = await this.prismaService.user.create({
            data: {
                email: createUserDto.email,
                password: createUserDto.password,
                role: createUserDto.role || 'USER',
            }
        });

        return newUser;
    }

    async updateUser(id: string, updateUserDto: UpdateUserDto) {
        const user = await this.prismaService.user.findUnique({
            where: { id },
        });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        const updatedUser = await this.prismaService.user.update({
            where: { id },
            data: updateUserDto
        });

        return updatedUser;
    }

    async deleteUser(id: string, reason: string) {
        console.log('🗑️ User silme işlemi başlatıldı:', { id, reason });
        
        const user = await this.prismaService.user.findUnique({
            where: { id },
        });

        if (!user) {
            console.log('❌ User bulunamadı:', id);
            throw new NotFoundException('User not found');
        }
        await this.prismaService.user.delete({
            where: { id },
        });

        console.log('✅ User başarıyla silindi:', id);
        return { message: 'User deleted successfully' };
    }
}

