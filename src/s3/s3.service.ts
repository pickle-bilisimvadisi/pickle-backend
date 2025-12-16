import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as https from 'https';
import * as aws4 from 'aws4';

@Injectable()
export class S3Service {
  private readonly accessKeyId: string;
  private readonly secretAccessKey: string;
  private readonly accountId: string;
  private readonly bucketName: string;
  private readonly host: string;

  constructor(private readonly configService: ConfigService) {
    this.accessKeyId = this.configService.get<string>('R2_ACCESS_KEY') || '';
    this.secretAccessKey = this.configService.get<string>('R2_SECRET_ACCESS_KEY') || '';
    this.accountId = this.configService.get<string>('R2_ACCOUNT_ID') || '';
    this.bucketName = this.configService.get<string>('R2_BUCKET_NAME') || '';

    if (!this.accessKeyId || !this.secretAccessKey) {
      throw new Error('R2_ACCESS_KEY and R2_SECRET_ACCESS_KEY must be configured');
    }

    if (!this.accountId) {
      throw new Error('R2_ACCOUNT_ID must be configured');
    }

    if (!this.bucketName) {
      throw new Error('R2_BUCKET_NAME must be configured');
    }

    // R2 endpoint host
    this.host = this.configService.get<string>('R2_ENDPOINT')?.replace(/^https?:\/\//, '').replace(/\/$/, '')
      || `${this.accountId}.r2.cloudflarestorage.com`;
  }

  /**
   * Upload a buffer to R2 using native HTTP requests
   */
  async uploadBuffer(
    key: string,
    buffer: Buffer,
    contentType: string = 'application/octet-stream',
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      // Path with bucket name (path-style)
      const path = `/${this.bucketName}/${key}`;

      // Prepare request options
      const options: any = {
        host: this.host,
        path: path,
        method: 'PUT',
        headers: {
          'Content-Type': contentType,
          'Content-Length': buffer.length.toString(),
        },
        body: buffer,
        service: 's3',
        region: 'auto',
      };

      // Sign the request with AWS Signature V4
      aws4.sign(options, {
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey,
      });

      // Make the HTTPS request
      const req = https.request(options, (res) => {
        let responseData = '';

        res.on('data', (chunk) => {
          responseData += chunk;
        });

        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
          } else {
            const error = new Error(
              `R2 upload failed with status ${res.statusCode}: ${responseData}`,
            );
            console.error('R2 Upload Error:', {
              statusCode: res.statusCode,
              headers: res.headers,
              body: responseData,
            });
            reject(error);
          }
        });
      });

      req.on('error', (error) => {
        console.error('R2 Upload Request Error:', error);
        reject(new Error(`Failed to upload file to R2: ${error.message}`));
      });

      // Write buffer to request
      req.write(buffer);
      req.end();
    });
  }

  /**
   * Download a buffer from R2 using native HTTP requests
   */
  async downloadBuffer(key: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      // Path with bucket name (path-style)
      const path = `/${this.bucketName}/${key}`;

      // Prepare request options
      const options: any = {
        host: this.host,
        path: path,
        method: 'GET',
        headers: {},
        service: 's3',
        region: 'auto',
      };

      // Sign the request with AWS Signature V4
      aws4.sign(options, {
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey,
      });

      // Make the HTTPS request
      const req = https.request(options, (res) => {
        const chunks: Buffer[] = [];

        res.on('data', (chunk) => {
          chunks.push(chunk);
        });

        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            const buffer = Buffer.concat(chunks);
            resolve(buffer);
          } else {
            const error = new Error(
              `R2 download failed with status ${res.statusCode}`,
            );
            console.error('R2 Download Error:', {
              statusCode: res.statusCode,
              headers: res.headers,
            });
            reject(error);
          }
        });
      });

      req.on('error', (error) => {
        console.error('R2 Download Request Error:', error);
        reject(new Error(`Failed to download file from R2: ${error.message}`));
      });

      req.end();
    });
  }

  /**
   * Delete a file from R2 using native HTTP requests
   */
  async deleteFile(key: string): Promise<void> {
    return new Promise((resolve, reject) => {
      // Path with bucket name (path-style)
      const path = `/${this.bucketName}/${key}`;

      // Prepare request options
      const options: any = {
        host: this.host,
        path: path,
        method: 'DELETE',
        headers: {},
        service: 's3',
        region: 'auto',
      };

      // Sign the request with AWS Signature V4
      aws4.sign(options, {
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey,
      });

      // Make the HTTPS request
      const req = https.request(options, (res) => {
        let responseData = '';

        res.on('data', (chunk) => {
          responseData += chunk;
        });

        res.on('end', () => {
          if (res.statusCode && (res.statusCode === 204 || res.statusCode === 200)) {
            resolve();
          } else {
            const error = new Error(
              `R2 delete failed with status ${res.statusCode}: ${responseData}`,
            );
            console.error('R2 Delete Error:', {
              statusCode: res.statusCode,
              headers: res.headers,
              body: responseData,
            });
            reject(error);
          }
        });
      });

      req.on('error', (error) => {
        console.error('R2 Delete Request Error:', error);
        reject(new Error(`Failed to delete file from R2: ${error.message}`));
      });

      req.end();
    });
  }

  /**
   * Get the bucket name
   */
  getBucketName(): string {
    return this.bucketName;
  }
}
