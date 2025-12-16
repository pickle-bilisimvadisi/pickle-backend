import {
  Controller,
  Post,
  Get,
  Param,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  UploadedFiles,
  ParseFilePipe,
  MaxFileSizeValidator,
  UnauthorizedException,
  BadRequestException,
  Req,
  Res,
  Body,
} from '@nestjs/common';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { memoryStorage, Multer } from 'multer';
import { Request, Response } from 'express';
import { JwtAuthGuard } from '../auth/guards/jwt.guard';
import { FileuploadService } from './fileupload.service';

@Controller('file')
export class FileuploadController {
  constructor(private readonly fileuploadService: FileuploadService) {}

  @UseGuards(JwtAuthGuard)
  @Post('upload')
  @UseInterceptors(FileInterceptor('file', { storage: memoryStorage() }))
  async uploadFile(
    @UploadedFile(
      new ParseFilePipe({
        validators: [new MaxFileSizeValidator({ maxSize: 25 * 1024 * 1024 })],
        fileIsRequired: true,
      }),
    )
    file: Multer.File,
    @Req() req: Request,
    @Body('relativePath') relativePath?: string,
  ) {
    const user = (req as Request & { user?: any }).user;
    if (!user?.userId) {
      throw new UnauthorizedException('Yetkilendirme başarısız.');
    }

    return this.fileuploadService.uploadEncrypted(
      file,
      user.userId as string,
      relativePath,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Post('upload-folder')
  @UseInterceptors(FilesInterceptor('files', 100, { storage: memoryStorage() }))
  async uploadFolder(
    @UploadedFiles() files: Multer.File[],
    @Req() req: Request,
  ) {
    const user = (req as Request & { user?: any }).user;
    if (!user?.userId) {
      throw new UnauthorizedException('Yetkilendirme başarısız.');
    }

    if (!files || files.length === 0) {
      throw new BadRequestException('Dosya bulunamadı.');
    }

    // Parse paths from request body (frontend should send 'paths' as JSON string in form-data)
    let pathsData: string[] = [];
    try {
      const pathsString = (req.body as any)?.paths;
      if (pathsString) {
        pathsData = typeof pathsString === 'string' ? JSON.parse(pathsString) : pathsString;
      }
    } catch (error) {
      console.warn('Could not parse paths data:', error);
    }

    // Match files with their paths
    // Frontend should send files in same order as paths array
    const filesWithPaths = files.map((file, index) => {
      const relativePath = pathsData[index] || file.originalname;
      return {
        file,
        relativePath,
      };
    });

    return this.fileuploadService.uploadMultipleEncrypted(
      filesWithPaths,
      user.userId as string,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Get('my-files')
  async getMyFiles(@Req() req: Request) {
    const user = (req as Request & { user?: any }).user;
    if (!user?.userId) {
      throw new UnauthorizedException('Yetkilendirme başarısız.');
    }

    return this.fileuploadService.getUserFiles(user.userId as string);
  }

  @Get(':id')
  async getFile(@Param('id') fileId: string) {
    return this.fileuploadService.getFileById(fileId as string);
  }

  @UseGuards(JwtAuthGuard)
  @Post(':id/download-link')
  async generateDownloadLink(
    @Param('id') fileId: string,
    @Req() req: Request,
  ) {
    const user = (req as Request & { user?: any }).user;
    if (!user?.userId) {
      throw new UnauthorizedException('Yetkilendirme başarısız.');
    }

    return this.fileuploadService.generateDownloadToken(fileId, user.userId as string);
  }

  @Get('download/:token')
  async downloadFile(
    @Param('token') token: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const user = (req as Request & { user?: any }).user;
    const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
      const fileData = await this.fileuploadService.downloadFileWithToken(
        token,
        user?.userId,
        typeof ipAddress === 'string' ? ipAddress : undefined,
      );

      res.setHeader('Content-Type', fileData.contentType);
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${encodeURIComponent(fileData.fileName)}"`,
      );
      res.setHeader('Content-Length', fileData.buffer.length.toString());

      res.send(fileData.buffer);
    } catch (error) {
      res.status(error.status || 500).json({
        statusCode: error.status || 500,
        message: error.message || 'Dosya indirme başarısız.',
      });
    }
  }
}
