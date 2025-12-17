import { Injectable, BadRequestException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import * as bcrypt from 'bcrypt';
import { AuthDto } from './dto/auth.dto';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { MailService } from 'src/mail/mail.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
    private readonly mailService: MailService,
  ) {
  }

  private validatePassword(password: string): void {
    const minLength = 6;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);

    if (password.length < minLength) {
      throw new BadRequestException(`Password must be at least ${minLength} characters long`);
    }

    if (!hasUpperCase) {
      throw new BadRequestException('Password must contain at least one uppercase letter');
    }

    if (!hasLowerCase) {
      throw new BadRequestException('Password must contain at least one lowercase letter');
    }

    if (!hasNumbers) {
      throw new BadRequestException('Password must contain at least one number');
    }
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userService.findByEmail(email);
    
    if (!user) {
        throw new BadRequestException('No user found with this email');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        throw new BadRequestException('Invalid email or password');
    }

    const { password: _, ...result } = user;
    return result;
  }



  async changeEmail(userId: string, newEmail: string, password: string) {
    const user = await this.userService.findById(userId);
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }

    if (user.email === newEmail) {
      throw new BadRequestException('New email cannot be the same as the old email');
    }

    const existingUser = await this.userService.findByEmail(newEmail);
    if (existingUser) {
      throw new BadRequestException('This email is already in use by another account');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const expiresAt = new Date();
    expiresAt.setUTCMinutes(expiresAt.getUTCMinutes() + 5);

    await this.prismaService.user.update({
      where: { id: user.id },
      data: { 
        verifyToken: hashedOtp,
        otpExpiry: expiresAt,
        tempEmail: newEmail
      }
    });

    await this.sendEmailChangeVerificationOtp(newEmail, otp);
    
    return {
      message: 'Verification OTP sent to your new email address. Please verify to complete email change.',
      newEmail: newEmail
    };
  }

  async verifyEmailChange(userId: string, newEmail: string, otp: string) {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      throw new BadRequestException('User not found with current email');
    }

    if (!user.verifyToken || !user.otpExpiry || !user.tempEmail) {
      throw new BadRequestException('No email change request found');
    }

    if (user.tempEmail !== newEmail) {
      throw new BadRequestException('New email does not match the pending email change request');
    }

    const currentTime = new Date();
    if (user.otpExpiry < currentTime) {
      throw new BadRequestException('Email change OTP has expired');
    }

    const isOtpValid = await bcrypt.compare(otp, user.verifyToken);
    if (!isOtpValid) {
      throw new BadRequestException('Invalid email change OTP');
    }

    const existingUser = await this.userService.findByEmail(newEmail);
    if (existingUser) {
      throw new BadRequestException('This email is already in use by another account');
    }

    const updatedUser = await this.prismaService.user.update({
      where: { id: user.id },
      data: { 
        email: newEmail,
        verifyToken: null,
        otpExpiry: null,
        tempEmail: null
      }
    });

    const payload = { 
      email: updatedUser.email, 
      sub: updatedUser.id,
      role: updatedUser.role,
    };

    return {
      message: 'Email changed successfully',
      access_token: this.jwtService.sign(payload),
      email: updatedUser.email,
      isVerified: updatedUser.isVerified,
    };
  }

  private async sendEmailChangeVerificationOtp(email: string, otp: string) {
    this.mailService.sendChangeEmailOtp(email, otp).catch(err => {
      console.error('Failed to enqueue change email OTP:', err);
    });
  }

  async forgotResetPassword(email: string, newPassword: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }

    const isNewPasswordValid = await bcrypt.compare(newPassword, user.password);
    if (isNewPasswordValid) {
      throw new BadRequestException('New password cannot be the same as the old password');
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.userService.updateUser(user.id, { password: hashedPassword });
    return {
      message: 'Password reset successfully',
    }
  }

  async register(dto: AuthDto) {
    try {
        const existingUsers = await this.prismaService.user.findMany({
          where: { 
            email: dto.email,
            isVerified: true
          }
        });
        console.log('Existing users check:', existingUsers);
        if (existingUsers.length > 0) {
          console.log('Existing verified users found:', existingUsers);
          throw new BadRequestException('User already exists with this email');
        }

        await this.cleanupExpiredUnverifiedUsers(dto.email);

        const existingPendingUser = await this.prismaService.user.findFirst({
          where: {
            pendingEmail: dto.email,
            isVerified: false
          }
        });

        this.validatePassword(dto.password);
        console.log('Password validated successfully');
        const hashedPassword = await bcrypt.hash(dto.password, 10);

        const pendingUserData = {
            email: dto.email,
            password: hashedPassword,
            type: 'register' 
        };

        let tempUser;
        
        if (existingPendingUser) {
          tempUser = await this.prismaService.user.update({
            where: { id: existingPendingUser.id },
            data: {
              pendingEmail: dto.email,
              password: null,
              isVerified: false,
            }
          });
        } else {
          console.log('Creating new temporary user for registration');
          tempUser = await this.prismaService.user.create({
            data: {
                email: dto.email,
                pendingEmail: dto.email,
                password: null,
                isVerified: false,
            }
          });
        }
        console.log('Temporary user created/updated:', tempUser);
        await this.generateAndSendVerificationOtp(dto.email, pendingUserData, tempUser.id);
        console.log('Verification OTP sent to email:', dto.email);
        return {
            email: dto.email,
            message: 'Registration initiated. Please verify your email with the OTP sent to complete registration.',
            emailSent: true,
            isVerified: false
        };
    } catch (error) {
        if (error instanceof BadRequestException) {
            throw new BadRequestException(error.message);
        }
        throw new InternalServerErrorException('Failed to create user');
    }
  }

  async forgotPasswordEmailSender(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }

    await this.generateAndSendOtp(user.email);
    
    return {
      message: 'One time password has been sent to your email',
    };
  }
  
  async verifyOtp(email: string, otp: string) {
    if (!email || !otp) {
      throw new BadRequestException('Email and OTP are required');
    }

    const user = await this.userService.findByEmail(email);
    
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }
    
    if (!user.otpCode || !user.otpExpiry) {
      throw new BadRequestException('No reset request found');
    }
    
    const currentTime = new Date();
    if (user.otpExpiry < currentTime) {
      throw new BadRequestException('One time password has expired');
    }
    
    const isOtpValid = await bcrypt.compare(otp, user.otpCode);
    if (!isOtpValid) {
      throw new BadRequestException('Invalid one time password');
    }
    
    await this.prismaService.user.update({
      where: { email },
      data: { 
        otpCode: null,
        otpExpiry: null
      }
    });
    
    return {
      message: 'One time password verified successfully',
    };
  }

  async resendForgotPasswordOtp(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }

    await this.generateAndSendOtp(user.email);
    
    return {
      message: 'Password reset OTP has been sent to your email',
    };
  }

  async resendVerificationOtp(email: string) {
    let user = await this.prismaService.user.findFirst({
      where: { pendingEmail: email }
    });
    
    if (!user) {
      user = await this.userService.findByEmail(email);
    }
    
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }

    if (user.isVerified) {
      throw new BadRequestException('Email is already verified');
    }

    let pendingData = null;
    if (user.verifyToken) {
      try {
        const parsedData = JSON.parse(user.verifyToken);
        if (parsedData.type) {
          const { otp, ...restData } = parsedData;
          pendingData = restData;
        }
      } catch {

      }
    }

    const emailToUse = pendingData?.email || user.email;
    
    await this.generateAndSendVerificationOtp(emailToUse, pendingData, user.id);
    
    return {
      message: 'Verification OTP has been sent to your email',
    };
  }

  async resendEmailChangeOtp(userId: string) {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId }
    });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (!user.tempEmail) {
      throw new BadRequestException('No email change request found');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const expiresAt = new Date();
    expiresAt.setUTCMinutes(expiresAt.getUTCMinutes() + 5);

    await this.prismaService.user.update({
      where: { id: user.id },
      data: { 
        verifyToken: hashedOtp,
        otpExpiry: expiresAt
      }
    });

    await this.sendEmailChangeVerificationOtp(user.tempEmail, otp);
    
    return {
      message: 'Email change OTP has been sent to your new email address',
      newEmail: user.tempEmail
    };
  }
  
  private async generateAndSendOtp(email: string) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    const hashedOtp = await bcrypt.hash(otp, 10);
    
    const expiresAt = new Date();
    expiresAt.setUTCMinutes(expiresAt.getUTCMinutes() + 5);
    
    await this.prismaService.user.update({
      where: { email },
      data: { 
        otpCode: hashedOtp,
        otpExpiry: expiresAt
      },
    });
    
    this.mailService.sendForgotPasswordOtp(email, otp).catch(err => {
      console.error('Failed to enqueue forgot password OTP:', err);
    });
  }

  private async generateAndSendVerificationOtp(email: string, pendingUserData?: any, userId?: string) {
    console.log('Generating verification OTP for email:', email);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log(otp);
    const hashedOtp = await bcrypt.hash(otp, 10);
    
    const expiresAt = new Date();
    expiresAt.setUTCMinutes(expiresAt.getUTCMinutes() + 5);
    
    const verifyTokenData = pendingUserData 
      ? JSON.stringify({ ...pendingUserData, otp: hashedOtp })
      : hashedOtp;
    
    if (userId) {
      await this.prismaService.user.update({
        where: { id: userId },
        data: { 
          verifyToken: verifyTokenData,
          otpExpiry: expiresAt
        },
      });
    } else {
      await this.prismaService.user.update({
        where: { email },
        data: { 
          verifyToken: verifyTokenData,
          otpExpiry: expiresAt
        },
      });
    }
    
    this.mailService.sendVerificationOtp(email, otp).catch(err => {
      console.error('Failed to enqueue verification OTP:', err);
    });
  }

  async login(user: any) {
    if (!user.isVerified) {
      return {
        message: 'Please verify your email address first.',
        isVerified: false,
        emailSent: false,
        user: {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          isVerified: user.isVerified
        }
      };
    }

    const payload = { 
      fullName: user.fullName, 
      email: user.email, 
      sub: user.id,
      isPremium: user.isPremium,
      isGuest: false,
      isAdmin: user.isAdmin || false,
    };

    const access_token = this.jwtService.sign(payload, {
      expiresIn: this.configService.get('JWT_EXPIRATION_TIME', '15m'),
    });

    const refreshPayload = { 
      email: user.email, 
      sub: user.id,
    };
    
    const refresh_token = this.jwtService.sign(refreshPayload, {
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRATION_TIME', '7d'),
      secret: this.configService.get('JWT_REFRESH_SECRET') || this.configService.get('JWT_SECRET'),
    });

    const refreshTokenExpiry = new Date();
    const refreshTokenExpiryDays = parseInt(this.configService.get('JWT_REFRESH_EXPIRATION_TIME', '7d').replace('d', '')) || 7;
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + refreshTokenExpiryDays);

    await this.prismaService.refreshToken.create({
      data: {
        token: refresh_token,
        userId: user.id,
        expiresAt: refreshTokenExpiry,
      }
    });

    return {
      access_token,
      refresh_token,
      email: user.email,
      fullName: user.fullName,
      isGuest: false,
      isVerified: user.isVerified,
      isAdmin: user.isAdmin || false,
    };
  }

  async refreshAccessToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET') || this.configService.get('JWT_SECRET'),
      });

      const storedRefreshToken = await this.prismaService.refreshToken.findUnique({
        where: { token: refreshToken },
        include: { user: true }
      });

      if (!storedRefreshToken) {
        throw new UnauthorizedException('Refresh token not found or has been revoked');
      }

      if (new Date() > storedRefreshToken.expiresAt) {
        await this.prismaService.refreshToken.delete({
          where: { id: storedRefreshToken.id }
        });
        throw new UnauthorizedException('Refresh token has expired');
      }

      const user = storedRefreshToken.user;

      const newPayload = { 
        email: user.email, 
        sub: user.id,
        isGuest: false,
      };

      const access_token = this.jwtService.sign(newPayload, {
        expiresIn: this.configService.get('JWT_EXPIRATION_TIME', '15m'),
      });

      return {
        access_token,
        email: user.email,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid refresh token');
    }
  }


  async resetPassword(email: string, newPassword: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }
    
    this.validatePassword(newPassword);

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.userService.updateUser(user.id, { 
      password: hashedPassword,
    });
    return {
      message: 'Password reset successfully',
    }
  }
  private async cleanupExpiredUnverifiedUsers(email: string) {
    try {
      const currentTime = new Date();
      const deletedCount = await this.prismaService.user.deleteMany({
        where: {
          pendingEmail: email,
          isVerified: false,
          otpExpiry: {
            lt: currentTime
          }
        }
      });

      if (deletedCount.count > 0) {
        console.log(`Cleaned up ${deletedCount.count} expired unverified users for email: ${email}`);
      }
    } catch (error) {
      console.error('Error cleaning up expired users:', error);
    }
  }

  private async getTokens(userId: string, email: string) {
    const payload = { sub: userId, email };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async getProfile(userId: string) {
    const user = await this.userService.findById(userId);
    return {
        ...user
    };
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string) {

    const user = await this.prismaService.user.findUnique({
      where: { id: userId }
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    this.validatePassword(newPassword);

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.userService.updateUser(userId, { password: hashedPassword });
    return {
      message: 'Password changed successfully',
    }
  }

  async verifyEmail(email: string, otp: string) {
    if (!email || !otp) {
      throw new BadRequestException('Email and OTP are required');
    }

    let user = await this.prismaService.user.findFirst({
      where: { pendingEmail: email }
    });
    
    if (!user) {
      user = await this.prismaService.user.findUnique({
        where: { email }
      });
    }
    
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }
    
    if (!user.verifyToken || !user.otpExpiry) {
      throw new BadRequestException('No verification request found');
    }
    
    const currentTime = new Date();
    console.log('Current time:', currentTime.toISOString());
    console.log('OTP expiry time:', user.otpExpiry?.toISOString());
    console.log('Time difference in minutes:', user.otpExpiry ? (user.otpExpiry.getTime() - currentTime.getTime()) / (1000 * 60) : 'No expiry set');
    
    if (user.otpExpiry < currentTime) {
      throw new BadRequestException('Verification OTP has expired');
    }
    
    let pendingData = null;
    let otpHash = user.verifyToken;
    
    try {
      const parsedData = JSON.parse(user.verifyToken);
      if (parsedData.otp) {
        pendingData = parsedData;
        otpHash = parsedData.otp;
      }
    } catch {
      otpHash = user.verifyToken;
    }
    
    const isOtpValid = await bcrypt.compare(otp, otpHash);
    if (!isOtpValid) {
      throw new BadRequestException('Invalid verification OTP');
    }
    
    let updatedUser;
    
    if (pendingData) {
      if (pendingData.type === 'register') {
        updatedUser = await this.prismaService.user.update({
          where: { id: user.id },
          data: {
            email: pendingData.email,
            password: pendingData.password,
            isVerified: true,
            verifyToken: null,
            otpExpiry: null,
            pendingEmail: null
          }
        });
      }
    } else {
      updatedUser = await this.prismaService.user.update({
        where: { email },
        data: { 
          isVerified: true,
          verifyToken: null,
          otpExpiry: null
        }
      });
    }
    
    const payload = { 
      email: updatedUser.email, 
      sub: updatedUser.id,
      role: updatedUser.role,
    };

    const access_token = this.jwtService.sign(payload, {
      expiresIn: this.configService.get('JWT_ACCESS_EXPIRES_IN', '10m'),
    });

    const refreshPayload = { 
      email: updatedUser.email, 
      sub: updatedUser.id,
    };
    
    const refresh_token = this.jwtService.sign(refreshPayload, {
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d'),
      secret: this.configService.get('JWT_REFRESH_SECRET') || this.configService.get('JWT_SECRET'),
    });

    const refreshTokenExpiry = new Date();
    const refreshTokenExpiryDays = parseInt(this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d').replace('d', '')) || 7;
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + refreshTokenExpiryDays);

    await this.prismaService.refreshToken.create({
      data: {
        token: refresh_token,
        userId: updatedUser.id,
        expiresAt: refreshTokenExpiry,
      }
    });

    return {
      message: 'Email verified successfully',
      access_token,
      refresh_token,
      email: updatedUser.email,
      isVerified: updatedUser.isVerified,
      role: updatedUser.role,
    };
  }

  async logout(refreshToken: string) {
    const deletedCount = await this.prismaService.refreshToken.deleteMany({
      where: { 
        token: refreshToken,
        expiresAt: {
          gt: new Date()
        },
        userId: {
          not: null
        }
      }
    });
    if (deletedCount.count > 0) {
      return {
        message: 'Logged out successfully',
      };
    } else {
      throw new BadRequestException('Invalid refresh token');
    }
  }

}