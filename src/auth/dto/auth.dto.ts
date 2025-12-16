import { IsEmail, IsString, IsOptional, Length, Matches } from 'class-validator';

export class AuthDto {
  @IsEmail({}, { message: 'Please enter a valid email address' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @Length(6, 128, { message: 'Password must be at least 6 characters long' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]/,
    {
      message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
    }
  )
  password: string;
} 