import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { UserSource } from '@prisma/client';

export interface OIDCClaims {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  preferred_username?: string;
  iss?: string;
}

@Injectable()
export class OIDCService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Extract provider identifier from issuer URL
   */
  extractProviderFromIssuer(issuer: string): string {
    try {
      const url = new URL(issuer);
      // Extract provider name from issuer (e.g., accounts.google.com -> google)
      const hostname = url.hostname;
      if (hostname.includes('google')) return 'google';
      if (hostname.includes('microsoft') || hostname.includes('login.microsoftonline.com'))
        return 'azure';
      if (hostname.includes('okta')) return 'okta';
      if (hostname.includes('auth0')) return 'auth0';
      // Default: use hostname as provider identifier
      return hostname.split('.')[0] || 'oidc';
    } catch {
      return 'oidc';
    }
  }

  /**
   * Find or create user from OIDC claims
   */
  async findOrCreateUserFromOIDC(claims: OIDCClaims, issuer: string): Promise<any> {
    const provider = this.extractProviderFromIssuer(issuer);
    const {
      sub,
      email,
      email_verified,
      name,
      given_name,
      family_name,
      picture,
      preferred_username,
    } = claims;

    if (!sub) {
      throw new Error('OIDC sub claim is required');
    }

    // First, try to find user by OIDC provider + sub (exact match)
    let user = await this.prisma.user.findFirst({
      where: {
        oidcProvider: provider,
        oidcSub: sub,
      },
    });

    if (user) {
      // Update last login
      await this.prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });
      return user;
    }

    // If not found by OIDC, try to find by email (for account linking)
    if (email) {
      user = await this.prisma.user.findUnique({
        where: { email },
      });

      if (user) {
        // Link OIDC account to existing user
        user = await this.prisma.user.update({
          where: { id: user.id },
          data: {
            oidcProvider: provider,
            oidcSub: sub,
            oidcIssuer: issuer,
            emailVerified: email_verified || user.emailVerified,
            lastLoginAt: new Date(),
            // Update avatar if provided and user doesn't have one
            avatar: user.avatar || picture || undefined,
          },
        });
        return user;
      }
    }

    // Create new user
    const firstName = given_name || name?.split(' ')[0] || email?.split('@')[0] || 'User';
    const lastName = family_name || name?.split(' ').slice(1).join(' ') || '';

    // Generate unique username
    const baseUsername =
      preferred_username || email?.split('@')[0] || `user_${sub.substring(0, 8)}`;
    const sanitizedBase = baseUsername.toLowerCase().replace(/[^a-z0-9]/g, '');
    let finalUsername = sanitizedBase;
    let counter = 1;

    while (await this.prisma.user.findUnique({ where: { username: finalUsername } })) {
      finalUsername = `${sanitizedBase}${counter}`;
      counter++;
    }

    user = await this.prisma.user.create({
      data: {
        email: email || `${sub}@oidc.local`,
        firstName,
        lastName,
        username: finalUsername,
        avatar: picture || undefined,
        emailVerified: email_verified || false,
        status: 'ACTIVE',
        role: 'MEMBER',
        source: UserSource.SSO,
        oidcProvider: provider,
        oidcSub: sub,
        oidcIssuer: issuer,
        lastLoginAt: new Date(),
      },
    });

    const userWithoutPassword: Omit<typeof user, 'password'> = Object.assign({}, user);
    delete (userWithoutPassword as any).password;
    return userWithoutPassword;
  }
}
