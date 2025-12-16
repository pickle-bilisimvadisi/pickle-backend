import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalFilters(new AllExceptionsFilter());
  app.use(cookieParser());
  
  app.enableShutdownHooks();

  await app.listen(process.env.PORT ?? 8080);

  console.log(`Application is running on: ${await app.getUrl()}`);
}

bootstrap();
