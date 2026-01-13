import { ApiProperty } from '@nestjs/swagger';

export class OIDCConfigDto {
  @ApiProperty({ description: 'Whether OIDC is enabled' })
  enabled: boolean;

  @ApiProperty({ description: 'OIDC provider name', required: false })
  providerName?: string;
}
