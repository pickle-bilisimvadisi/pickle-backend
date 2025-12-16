import { IsString, IsBoolean, IsOptional, Length, IsEmail, IsEnum } from 'class-validator';

export class CreateUserDto {
    @IsEmail()
    @Length(1, 50)
    email: string;

    @IsString()
    password: string;

    @IsOptional()
    @IsEnum(['USER', 'ADMIN'])
    role?: 'USER' | 'ADMIN';
}