import { AuthService } from './auth.service';
import {
    Body,
    Controller,
    Get,
    Post,
} from '@nestjs/common';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('/signUp')
    signUp(@Body() dto: AuthDto) {
        console.log("dto", dto)
        return this.authService.signUp(dto);
    }

    @Post('/signIn')
    signIn(@Body() dto: AuthDto) {
        return this.authService.signIn(dto);
    }
    @Get()
    getHello(): string {
        return this.authService.getHello();
    }
}
