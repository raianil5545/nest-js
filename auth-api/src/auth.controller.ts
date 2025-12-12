import {
  Controller,
  Post,
  Get,
  Body,
  Headers,
  UnauthorizedException,
} from "@nestjs/common";
import { AuthService } from "./auth.service";

@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("register")
  async register(
    @Body() body: { email: string; name: string; password: string }
  ) {
    return this.authService.register(body.email, body.name, body.password);
  }

  @Post("signin")
  async signin(@Body() body: { email: string; password: string }) {
    return this.authService.signin(body.email, body.password);
  }

  @Get("validate-token")
  async ValidateToken(@Headers("authorization") authHeader: string) {
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw new UnauthorizedException("Invalid or missing token");
    }

    const token = authHeader.split(" ")[1];
    return this.authService.vaidateToken(token);
  }
}
