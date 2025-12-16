import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    HttpStatus,
  } from '@nestjs/common';
  
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();

        let status = HttpStatus.INTERNAL_SERVER_ERROR;
        let message: string | string[] = 'Internal server error';

        if (exception instanceof HttpException) {
        status = exception.getStatus();
        const res = exception.getResponse();

        message = typeof res === 'string' ? res : (res as any).message || message;
        }

        response.status(status).json({
        status: 'error',
        message: Array.isArray(message) ? message.join(', ') : message,
        });
    }
}
  