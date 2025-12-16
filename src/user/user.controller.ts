import { Controller, Get, Post, Patch, Delete, Param, Body, UseGuards, Req } from '@nestjs/common';
import { UserService } from './user.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';
import { AdminGuard } from 'src/auth/guards/admin.guard';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @Get('me')
    @UseGuards(JwtAuthGuard)
    getMe(@Req() req) {
        return this.userService.findById(req.user.userId);
    }

    @Get()
    @UseGuards(JwtAuthGuard, AdminGuard)
    getUsers(@Req() req) {
        return this.userService.findAll(req.user.userId);
    }
 
    @Get(':id')
    @UseGuards(JwtAuthGuard, AdminGuard)
    getUser(@Param('id') id: string) {
        return this.userService.findById(id);
    }

    @Patch(':id')
    @UseGuards(JwtAuthGuard)
    updateUser(@Body() updateUserDto: UpdateUserDto, @Req() req) {
        return this.userService.updateUser(req.user.userId, updateUserDto);
    }

    @Delete(':id')
    @UseGuards(JwtAuthGuard, AdminGuard)
    deleteUser(@Param('id') id: string, @Body() body: { reason: string }) {
        console.log("🗑️ User silme isteği:", { id, reason: body.reason });
        return this.userService.deleteUser(id, body.reason);
    }

    @Delete()
    @UseGuards(JwtAuthGuard)
    deleteSelf(@Req() req, @Body() body: { reason: string }) {
        console.log("selamlar3")
        return this.userService.deleteUser(req.user.userId, body.reason);
    }
}
