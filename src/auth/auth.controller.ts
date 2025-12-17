import { Controller, Post, Body, UseGuards, Request, Get, UnauthorizedException, HttpCode, HttpStatus, Patch, Req, Query, Res, BadRequestException } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt.guard';
import { AuthDto } from './dto/auth.dto';
import { CreateGuestDto, UpdateGuestDto, ConvertGuestDto } from './dto/guest-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() body: AuthDto) {
    return await this.authService.register(body);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() body: { email: string; password: string }) {
      const user = await this.authService.validateUser(body.email, body.password);
      return this.authService.login(user);
  }

  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() body: { email: string; otp: string }) {
    return this.authService.verifyEmail(body.email, body.otp);
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() body: { email: string }) {
    return this.authService.forgotPasswordEmailSender(body.email);
  }

  @Post('resend-forgot-password-otp')
  @HttpCode(HttpStatus.OK)
  async resendForgotPasswordOtp(@Body() body: { email: string }) {
    return this.authService.resendForgotPasswordOtp(body.email);
  }

  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(@Body() body: { email: string; otp: string }) {
    return this.authService.verifyOtp(body.email, body.otp);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() body: { email: string; new_password: string }) {
    return this.authService.resetPassword(body.email, body.new_password);
  }

  @Post('resend-verify-email-otp')
  @HttpCode(HttpStatus.OK)
  async resendVerificationOtp(@Body() body: { email: string }) {
    return this.authService.resendVerificationOtp(body.email);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Req() req) {
    return this.authService.getProfile(req.user.userId);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshAccessToken(@Body() body: { refresh_token: string }) {
    return this.authService.refreshAccessToken(body.refresh_token);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Body() body: { refresh_token: string }) {
    return this.authService.logout(body.refresh_token);
  }
}
