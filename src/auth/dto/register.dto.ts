import { Role } from "@prisma/client";
import { IsEmail, IsNotEmpty, IsOptional, IsString, IsBoolean } from "class-validator";

export class RegisterDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsBoolean()
  @IsOptional()
  role: Role;
}