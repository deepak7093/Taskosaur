import {
  Controller,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  Get,
  Param,
  Query,
  ParseUUIDPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiQuery } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { AuthResponseDto, RefreshTokenDto } from './dto/auth-response.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyResetTokenResponseDto } from './dto/verify-reset-token.dto';
import { SetupAdminDto } from './dto/setup-admin.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Public } from './decorators/public.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import { SetupService } from './services/setup.service';
import { AccessControlService, AccessResult } from 'src/common/access-control.utils';
import { OIDCStrategy } from './strategies/oidc.strategy';
import { OIDCConfigDto } from './dto/oidc-config.dto';
import { Res } from '@nestjs/common';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
export enum ScopeType {
  ORGANIZATION = 'organization',
  WORKSPACE = 'workspace',
  PROJECT = 'project',
  TASK = 'task',
}
@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  private readonly oidcStateStore = new Map<string, { timestamp: number }>();

  constructor(
    private readonly authService: AuthService,
    private readonly setupService: SetupService,
    private readonly accessControlService: AccessControlService,
    private readonly oidcStrategy: OIDCStrategy,
    private readonly configService: ConfigService,
  ) {
    // Clean up expired states every 10 minutes
    setInterval(
      () => {
        const now = Date.now();
        for (const [state, data] of this.oidcStateStore.entries()) {
          if (now - data.timestamp > 10 * 60 * 1000) {
            // 10 minutes
            this.oidcStateStore.delete(state);
          }
        }
      },
      10 * 60 * 1000,
    );
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User login' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: AuthResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid credentials',
  })
  async login(@Body() loginDto: LoginDto): Promise<AuthResponseDto> {
    return this.authService.login(loginDto);
  }

  @Public()
  @Post('register')
  @ApiOperation({ summary: 'User registration' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({
    status: 201,
    description: 'Registration successful',
    type: AuthResponseDto,
  })
  @ApiResponse({
    status: 409,
    description: 'User already exists',
  })
  async register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
    return this.authService.register(registerDto);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiBody({ type: RefreshTokenDto })
  @ApiResponse({
    status: 200,
    description: 'Token refreshed successfully',
    type: AuthResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid refresh token',
  })
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto): Promise<AuthResponseDto> {
    return this.authService.refreshToken(refreshTokenDto.refresh_token);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User logout' })
  @ApiResponse({
    status: 200,
    description: 'Logout successful',
  })
  async logout(@CurrentUser() user: any): Promise<{ message: string }> {
    await this.authService.logout(user.id as string);
    return { message: 'Logout successful' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
  })
  getProfile(@CurrentUser() user: any): any {
    return user;
  }
  @UseGuards(JwtAuthGuard)
  @Get('access-control')
  @ApiOperation({ summary: 'Get user access for a specific resource' })
  @ApiQuery({
    name: 'scope',
    enum: ScopeType,
    description: 'The scope type (organization, workspace, project, task)',
    required: true,
  })
  @ApiQuery({
    name: 'id',
    description: 'The UUID of the resource',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'Access information retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        isElevated: { type: 'boolean' },
        role: {
          type: 'string',
          enum: ['SUPER_ADMIN', 'OWNER', 'MANAGER', 'MEMBER', 'VIEWER'],
        },
        canChange: { type: 'boolean' },
        userId: { type: 'string' },
        scopeId: { type: 'string' },
        scopeType: { type: 'string' },
      },
    },
  })
  async getResourceAccess(
    @Query('scope') scope: ScopeType,
    @Query('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: any,
  ): Promise<AccessResult> {
    return this.accessControlService.getResourceAccess(scope, id, user.id as string);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Send password reset email' })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Password reset email sent successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        message: {
          type: 'string',
          example: 'Password reset instructions sent to your email',
        },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ): Promise<{ success: boolean; message: string }> {
    await this.authService.forgotPassword(forgotPasswordDto.email);
    return {
      success: true,
      message: 'Password reset instructions sent to your email',
    };
  }

  @Public()
  @Get('verify-reset-token/:token')
  @ApiOperation({ summary: 'Verify password reset token' })
  @ApiResponse({
    status: 200,
    description: 'Token verification result',
    type: VerifyResetTokenResponseDto,
  })
  async verifyResetToken(@Param('token') token: string): Promise<VerifyResetTokenResponseDto> {
    const { isValid } = await this.authService.verifyResetToken(token);
    return {
      valid: isValid,
      message: isValid ? 'Token is valid' : 'Invalid or expired token',
    };
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset user password with token' })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Password reset successful',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        message: {
          type: 'string',
          example: 'Password has been reset successfully',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid token or password validation failed',
  })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<{ success: boolean; message: string }> {
    // Validate that passwords match
    if (resetPasswordDto.password !== resetPasswordDto.confirmPassword) {
      throw new Error('Passwords do not match');
    }

    await this.authService.resetPassword(resetPasswordDto.token, resetPasswordDto.password);
    return {
      success: true,
      message: 'Password has been reset successfully',
    };
  }

  @Public()
  @Get('setup/required')
  @ApiOperation({ summary: 'Check if system setup is required' })
  @ApiResponse({
    status: 200,
    description: 'Setup requirement status',
    schema: {
      type: 'object',
      properties: {
        required: { type: 'boolean' },
        canSetup: { type: 'boolean' },
        message: { type: 'string' },
      },
    },
  })
  async isSetupRequired() {
    const required = await this.setupService.isSetupRequired();
    const { canSetup, message } = await this.setupService.validateSetupState();
    return { required, canSetup, message };
  }

  @Public()
  @Post('setup')
  @ApiOperation({ summary: 'Setup super admin user (first-time setup only)' })
  @ApiBody({ type: SetupAdminDto })
  @ApiResponse({
    status: 201,
    description: 'Super admin created successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean' },
        message: { type: 'string' },
        user: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            email: { type: 'string' },
            firstName: { type: 'string' },
            lastName: { type: 'string' },
            username: { type: 'string' },
            role: { type: 'string' },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 409,
    description: 'Setup already completed or in progress',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid setup data',
  })
  async setupSuperAdmin(@Body() setupAdminDto: SetupAdminDto): Promise<AuthResponseDto> {
    return this.setupService.setupSuperAdmin(setupAdminDto);
  }

  @Public()
  @Get('oidc/config')
  @ApiOperation({ summary: 'Get OIDC configuration' })
  @ApiResponse({
    status: 200,
    description: 'OIDC configuration',
    type: OIDCConfigDto,
  })
  getOIDCConfig(): OIDCConfigDto {
    const enabled = this.configService.get<boolean>('app.oidc.enabled') || false;
    const issuer = this.configService.get<string>('app.oidc.issuer') || '';

    let providerName: string | undefined;
    if (enabled && issuer) {
      try {
        const url = new URL(issuer);
        const hostname = url.hostname;
        if (hostname.includes('google')) providerName = 'Google';
        else if (hostname.includes('microsoft') || hostname.includes('login.microsoftonline.com'))
          providerName = 'Microsoft';
        else if (hostname.includes('okta')) providerName = 'Okta';
        else if (hostname.includes('auth0')) providerName = 'Auth0';
        else providerName = 'OIDC';
      } catch {
        providerName = 'OIDC';
      }
    }

    return {
      enabled,
      providerName: enabled ? providerName : undefined,
    };
  }

  @Public()
  @Get('oidc/login')
  @ApiOperation({ summary: 'Initiate OIDC login' })
  @ApiResponse({
    status: 302,
    description: 'Redirect to OIDC provider',
  })
  async initiateOIDCLogin(@Res() res: Response) {
    const enabled = this.configService.get<boolean>('app.oidc.enabled') || false;
    if (!enabled) {
      return res.status(404).json({ message: 'OIDC is not enabled' });
    }

    try {
      const callbackUrl = this.configService.get<string>('app.oidc.callbackUrl') || '';

      // Generate state parameter for CSRF protection
      const state = crypto.randomBytes(32).toString('hex');
      this.oidcStateStore.set(state, { timestamp: Date.now() });

      const authUrl = await this.oidcStrategy.getAuthorizationUrl(callbackUrl, state);
      return res.redirect(authUrl);
    } catch (error) {
      console.error('OIDC login initiation error:', error);
      return res.status(500).json({ message: 'Failed to initiate OIDC login' });
    }
  }

  @Public()
  @Get('oidc/callback')
  @ApiOperation({ summary: 'Handle OIDC callback' })
  @ApiResponse({
    status: 302,
    description: 'Redirect to frontend with tokens',
  })
  async handleOIDCCallback(
    @Res() res: Response,
    @Query('code') code: string,
    @Query('state') state: string,
  ) {
    const enabled = this.configService.get<boolean>('app.oidc.enabled') || false;
    if (!enabled) {
      return res.status(404).json({ message: 'OIDC is not enabled' });
    }

    try {
      // Verify state parameter
      const stateData = this.oidcStateStore.get(state || '');
      if (!state || !stateData) {
        const frontendUrl =
          this.configService.get<string>('FRONTEND_URL') || 'http://localhost:3000';
        return res.redirect(`${frontendUrl}/login?error=invalid_state`);
      }

      // Clear state from store
      this.oidcStateStore.delete(state);

      const callbackUrl = this.configService.get<string>('app.oidc.callbackUrl') || '';
      const frontendUrl = this.configService.get<string>('FRONTEND_URL') || 'http://localhost:3000';
      const issuer = this.configService.get<string>('app.oidc.issuer') || '';

      // Exchange code for tokens
      const { claims } = await this.oidcStrategy.callback(callbackUrl, { code, state });

      // Authenticate user
      const authResponse = await this.authService.handleOIDCCallback(claims, issuer);

      // Redirect to frontend with tokens
      const redirectUrl = new URL(`${frontendUrl}/auth/oidc/callback`);
      redirectUrl.searchParams.set('access_token', authResponse.access_token);
      if (authResponse.refresh_token) {
        redirectUrl.searchParams.set('refresh_token', authResponse.refresh_token);
      }

      return res.redirect(redirectUrl.toString());
    } catch (error: unknown) {
      console.error('OIDC callback error:', error);
      const frontendUrl = this.configService.get<string>('FRONTEND_URL') || 'http://localhost:3000';
      const errorMessage = error instanceof Error ? error.message : 'oidc_auth_failed';
      return res.redirect(`${frontendUrl}/login?error=${encodeURIComponent(errorMessage)}`);
    }
  }
}
