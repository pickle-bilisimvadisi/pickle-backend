import { Process, Processor } from '@nestjs/bull';
import { Job } from 'bull';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailJobData } from './mail.service';
import * as nodemailer from 'nodemailer';

@Injectable()
@Processor('mail')
export class MailProcessor {
  private readonly logger = new Logger(MailProcessor.name);
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService) {
    this.initializeTransporter();
  }

  private initializeTransporter() {
    try {
      const emailHost = this.configService.get<string>('EMAIL_HOST');
      const emailPort = this.configService.get<string>('EMAIL_PORT');
      const emailUser = this.configService.get<string>('EMAIL_USER');
      const emailPassword = this.configService.get<string>('EMAIL_PASSWORD');

      if (!emailHost || !emailPort || !emailUser || !emailPassword) {
        this.logger.error('❌ Email configuration is missing. Please check your environment variables.');
        throw new Error('Email configuration is incomplete');
      }

      this.transporter = nodemailer.createTransport({
        host: emailHost,
        port: parseInt(emailPort, 10),
        secure: emailPort === '465',
        auth: {
          user: emailUser,
          pass: emailPassword,
        },
      });

      this.logger.log('✅ Mail transporter initialized successfully');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(`❌ Failed to initialize mail transporter: ${errorMessage}`, errorStack);
      throw error;
    }
  }

  @Process('send-mail')
  async handleSendMail(job: Job<MailJobData>) {
    const { type, email, otp } = job.data;
    this.logger.log(`📧 Processing mail job ${job.id} of type ${type} for ${email}`);

    try {
      if (!this.transporter) {
        throw new Error('Mail transporter is not initialized');
      }

      const mailOptions = this.buildMailOptions(type, email, otp);

      const info = await this.transporter.sendMail(mailOptions);
      
      this.logger.log(`✅ Mail job ${job.id} sent successfully to ${email}. MessageId: ${info.messageId}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(
        `❌ Failed to send mail job ${job.id} to ${email}: ${errorMessage}`,
        errorStack,
      );
      throw error;
    }
  }

  private buildMailOptions(type: MailJobData['type'], email: string, otp: string) {
    const from = `"Menthera" <${this.configService.get('EMAIL_USER')}>`;

    if (type === 'change-email-otp') {
      return {
        from,
        to: email,
        subject: 'Email Change Verification',
        html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Hello</h2>
          <p>We received a request to change your email address to this address. Please use the following OTP to verify your new email:</p>
          <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold;">
            ${otp}
          </div>
          <p>This OTP will expire in 5 minutes.</p>
          <p>If you didn't request this email change, please ignore this email and contact support.</p>
          <p>Best regards,<br>Menthera Team</p>
        </div>
      `,
      };
    }

    if (type === 'forgot-password-otp') {
      return {
        from,
        to: email,
        subject: 'Password Reset Mail',
        html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Hello</h2>
          <p>We received a request to reset your password. Please use the following OTP to proceed:</p>
          <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold;">
            ${otp}
          </div>
          <p>This OTP will expire in 5 minutes.</p>
          <p>If you didn't request a password reset, please ignore this email.</p>
          <p>Best regards,<br>Menthera Team</p>
        </div>
      `,
      };
    }

    // verification-otp
    return {
      from,
      to: email,
      subject: 'Email Verification Required',
      html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Hello</h2>
        <p>Thank you for registering with Menthera. Please use the following OTP to verify your email address:</p>
        <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold;">
          ${otp}
        </div>
        <p>This OTP will expire in 5 minutes.</p>
        <p>If you didn't register for Menthera, please ignore this email.</p>
        <p>Best regards,<br>Menthera Team</p>
      </div>
    `,
    };
  }
}


