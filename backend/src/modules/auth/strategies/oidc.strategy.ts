import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore - openid-client types are not perfect
import { Issuer, Client } from 'openid-client';

@Injectable()
export class OIDCStrategy {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private client: any = null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private issuer: any = null;

  constructor(private readonly configService: ConfigService) {}

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getClient(): Promise<any> {
    if (this.client) {
      return this.client;
    }

    const issuerUrl = this.configService.get<string>('app.oidc.issuer');
    if (!issuerUrl) {
      throw new Error('OIDC issuer URL is not configured');
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call
      this.issuer = await Issuer.discover(issuerUrl);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call
      this.client = new this.issuer.Client({
        client_id: this.configService.get<string>('app.oidc.clientId') || '',
        client_secret: this.configService.get<string>('app.oidc.clientSecret') || '',
        response_types: ['code'],
      });

      return this.client;
    } catch (error) {
      console.error('Failed to initialize OIDC client:', error);
      throw error;
    }
  }

  async getAuthorizationUrl(redirectUri: string, state: string): Promise<string> {
    const client = await this.getClient();
    const scope = this.configService.get<string>('app.oidc.scope') || 'openid profile email';

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call
    return client.authorizationUrl({
      redirect_uri: redirectUri,
      scope,
      state,
    });
  }

  async callback(redirectUri: string, params: any): Promise<any> {
    const client = await this.getClient();
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    const tokenset = await client.callback(redirectUri, params);

    if (!tokenset.id_token) {
      throw new Error('No ID token received from OIDC provider');
    }

    // Verify the ID token
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    const claims = await client.verifyIdToken(tokenset.id_token);

    return { tokenset, claims };
  }
}
