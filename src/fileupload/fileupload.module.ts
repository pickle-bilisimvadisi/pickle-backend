import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { FileuploadController } from './fileupload.controller';
import { FileuploadService } from './fileupload.service';
import { PrismaModule } from '../prisma/prisma.module';
import { S3Module } from '../s3/s3.module';

@Module({
  imports: [ConfigModule, PrismaModule, S3Module],
  controllers: [FileuploadController],
  providers: [FileuploadService],
})
export class FileuploadModule {}
