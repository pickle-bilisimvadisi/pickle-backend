import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Role, User } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  private readonly accessExpiresIn: string | number =
    process.env.JWT_ACCESS_EXPIRES_IN ?? '15m';
  private readonly refreshExpiresIn: string | number =
    process.env.JWT_REFRESH_EXPIRES_IN ?? '7d';
  private readonly refreshSecret =
    process.env.JWT_REFRESH_SECRET ??
    process.env.JWT_SECRET ??
    'dev-secret-change-me';

  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async validateUser(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }

  async login(user: Pick<User, 'id' | 'email' | 'role'>) {
    await this.prisma.refreshToken.deleteMany({ where: { userId: user.id } });

    const { accessToken, refreshToken } = await this.generateTokens(user);
    const refreshTokenExpiresAt = this.computeRefreshExpiryDate();

    await this.storeRefreshToken(user.id, refreshToken, refreshTokenExpiresAt);

    return {
      accessToken,
      refreshToken,
      refreshTokenExpiresAt: refreshTokenExpiresAt.toISOString(),
    };
  }

  async refreshTokens(refreshToken: string) {
    let payload: { sub: number; email: string; role: string };

    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.refreshSecret,
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    await this.prisma.refreshToken.deleteMany({
      where: { expiresAt: { lte: new Date() } },
    });

    const storedToken = await this.findMatchingRefreshToken(
      payload.sub,
      refreshToken,
    );
    if (!storedToken) {
      throw new UnauthorizedException('Refresh token is not recognized');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    await this.prisma.refreshToken.deleteMany({ where: { userId: user.id } });

    const tokens = await this.generateTokens(user);
    const refreshTokenExpiresAt = this.computeRefreshExpiryDate();

    await this.storeRefreshToken(
      user.id,
      tokens.refreshToken,
      refreshTokenExpiresAt,
    );

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: refreshTokenExpiresAt.toISOString(),
    };
  }

  async register(body: RegisterDto) {
    const user = await this.prisma.user.create({
      data: { email: body.email, password: body.password, role: body.role ?? Role.USER },
    });
    return {
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    };
  }

  private async generateTokens(user: Pick<User, 'id' | 'email' | 'role'>) {
    const payload = { sub: user.id, email: user.email, role: user.role };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        expiresIn: this.accessExpiresIn as any,
      }),
      this.jwtService.signAsync(payload, {
        secret: this.refreshSecret,
        expiresIn: this.refreshExpiresIn as any,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  private async storeRefreshToken(
    userId: number,
    refreshToken: string,
    expiresAt: Date,
  ) {
    const hashedToken = await bcrypt.hash(refreshToken, 10);

    await this.prisma.refreshToken.create({
      data: { token: hashedToken, userId, expiresAt },
    });
  }

  private computeRefreshExpiryDate() {
    const ms = this.expiresInToMs(this.refreshExpiresIn);
    return new Date(Date.now() + ms);
  }

  private expiresInToMs(expiresIn: string | number): number {
    if (typeof expiresIn === 'number') {
      return expiresIn * 1000;
    }

    const match = /^(\d+)([smhd])$/.exec(expiresIn);
    if (!match) {
      return 7 * 24 * 60 * 60 * 1000;
    }

    const value = Number(match[1]);
    const unit = match[2];

    const unitMap: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };

    return value * unitMap[unit];
  }

  private async findMatchingRefreshToken(
    userId: number,
    refreshToken: string,
  ) {
    const tokens = await this.prisma.refreshToken.findMany({
      where: { userId, expiresAt: { gt: new Date() } },
    });

    for (const token of tokens) {
      const isMatch = await bcrypt.compare(refreshToken, token.token);
      if (isMatch) {
        return token;
      }
    }

    return null;
  }

}
