import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';

export type MailJobType = 'verification-otp' | 'forgot-password-otp' | 'change-email-otp';

export interface MailJobData {
  type: MailJobType;
  email: string;
  otp: string;
}

@Injectable()
export class MailService {
  constructor(
    @InjectQueue('mail') private readonly mailQueue: Queue<MailJobData>,
  ) {}

  async enqueueVerificationOtp(email: string, otp: string) {
    await this.enqueueMailJob('verification-otp', email, otp);
  }

  async enqueueForgotPasswordOtp(email: string, otp: string) {
    await this.enqueueMailJob('forgot-password-otp', email, otp);
  }

  async enqueueChangeEmailOtp(email: string, otp: string) {
    await this.enqueueMailJob('change-email-otp', email, otp);
  }

  private async enqueueMailJob(type: MailJobType, email: string, otp: string) {
    try {
      await this.mailQueue.add(
        'send-mail',
        {
          type,
          email,
          otp
        },
        {
          attempts: 5,
          backoff: {
            type: 'exponential',
            delay: 2000,
          },
          removeOnComplete: true,
          removeOnFail: false,
        },
      );
    } catch (error) {
      console.error('❌ Failed to enqueue mail job:', error);
      throw new InternalServerErrorException('Failed to enqueue email job');
    }
  }
}


