import { IsEmail, IsEnum, IsNotEmpty, IsString } from 'class-validator';
import { Role } from '@prisma/client';

export class LoginDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  @IsEnum(Role)
  role: Role;
}