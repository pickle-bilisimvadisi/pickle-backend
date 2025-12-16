import { IsString, IsOptional, IsUUID } from 'class-validator';

export class CreateGuestDto {
    @IsString()
    @IsOptional()
    fullName?: string;
}

export class UpdateGuestDto {
    @IsUUID('4')
    deviceToken: string;
}

export class ConvertGuestDto {
    @IsString()
    email: string;

    @IsString()
    password: string;

    @IsString()
    fullName: string;

    @IsString()
    @IsOptional()
    referralCode?: string;
} 