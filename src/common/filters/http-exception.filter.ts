import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    let message: string;

    if (typeof exceptionResponse === 'string') {
      message = exceptionResponse;
    } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
      const responseObj = exceptionResponse as any;
      
      // Handle different error response formats
      if (responseObj.message) {
        if (Array.isArray(responseObj.message)) {
          message = responseObj.message.join(', ');
        } else {
          message = responseObj.message;
        }
      } else if (responseObj.error) {
        message = responseObj.error;
      } else {
        message = exception.message || 'An error occurred';
      }
    } else {
      message = exception.message || 'An error occurred';
    }

    response.status(status).json({
      status: 'error',
      message,
    });
  }
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    const status = exception instanceof HttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const message = exception instanceof HttpException
      ? this.getErrorMessage(exception)
      : 'Internal server error';

    response.status(status).json({
      status: 'error',
      message,
    });
  }

  private getErrorMessage(exception: HttpException): string {
    const exceptionResponse = exception.getResponse();
    
    if (typeof exceptionResponse === 'string') {
      return exceptionResponse;
    } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
      const responseObj = exceptionResponse as any;
      
      if (responseObj.message) {
        if (Array.isArray(responseObj.message)) {
          return responseObj.message.join(', ');
        } else {
          return responseObj.message;
        }
      } else if (responseObj.error) {
        return responseObj.error;
      }
    }
    
    return exception.message || 'An error occurred';
  }
}
