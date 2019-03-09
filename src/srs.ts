import { createHmac } from 'crypto';

export interface SRSOptions {
  separator: '=' | '-' | '+';
  maxAge: number;
  secret: string;
}

const SEPARATORS: SRSOptions['separator'][] = ['=', '-', '+'];

const TIME_BASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TIME_PRECISION = 60 * 60 * 24;
const TIME_BASE_BITS = 5;
const TIME_SLOTS = 1 << (TIME_BASE_BITS << 1);

const SRS0_REGEX = new RegExp(
  `SRS0[\\-=+]([0-9a-f]{4})=([${TIME_BASE_CHARS}]{2})=([^=]*)=(.*)`
);
const SRS1_REGEX = new RegExp('SRS1[\\-=+]([0-9a-f]{4})=([^=]*)=(.*)');

export class SRS {
  opt: SRSOptions = {
    separator: '=',
    maxAge: 30,
    secret: ''
  };

  constructor(opt: Partial<SRSOptions> = {}) {
    Object.assign(this.opt, opt);
    if (!this.opt.secret) throw new TypeError('Missing secret');
    if (SEPARATORS.indexOf(this.opt.separator) == -1)
      throw new TypeError(`Separator must be ${SEPARATORS.join(', ')}`);
  }

  private validateTimestamp(timestamp: string): void {
    let then = 0;
    for (let i = 0; i < timestamp.length; i++) {
      then =
        (then << TIME_BASE_BITS) |
        TIME_BASE_CHARS.indexOf(timestamp[i].toUpperCase());
    }

    let now = Math.round(Date.now() / 1000 / TIME_PRECISION) % TIME_SLOTS;
    while (now < then) {
      now = now + TIME_SLOTS;
    }

    if (now > then + this.opt.maxAge) throw new TypeError('Expired timestamp');
  }

  private static timestamp(): string {
    let now = Math.round(Date.now() / 1000 / TIME_PRECISION);
    let str = TIME_BASE_CHARS[now & ((1 << TIME_BASE_BITS) - 1)];
    now = now >> TIME_BASE_BITS;
    str = TIME_BASE_CHARS[now & ((1 << TIME_BASE_BITS) - 1)] + str;
    return str;
  }

  private hash(...data: string[]): string {
    return createHmac('sha256', this.opt.secret)
      .update(data.join(''))
      .digest('hex')
      .substr(0, 4);
  }

  rewrite(local: string, domain: string): string {
    if (local.startsWith('SRS0')) {
      // Create a guarded address.
      const guarded = local.substring(4);
      return (
        'SRS1' +
        this.opt.separator +
        this.hash(domain, guarded) +
        this.opt.separator +
        domain +
        this.opt.separator +
        guarded
      );
    } else if (local.startsWith('SRS1')) {
      const match = SRS1_REGEX.exec(local);
      if (!match) throw new Error('Invalid SRS1 address');

      return (
        'SRS1' +
        this.opt.separator +
        this.hash(match[2], match[3]) +
        '=' +
        match[2] +
        '=' +
        match[3]
      );
    }

    const timestamp = SRS.timestamp();

    return (
      'SRS0' +
      this.opt.separator +
      this.hash(timestamp, domain, local) +
      '=' +
      timestamp +
      '=' +
      domain +
      '=' +
      local
    );
  }

  reverse(address: string): string {
    if (address.startsWith('SRS0')) {
      const match = SRS0_REGEX.exec(address);
      if (!match) throw new Error('Invalid SRS0');

      const [, hash, timestamp, domain, local] = match;

      if (this.hash(timestamp, domain, local) != hash)
        throw new TypeError('Bad signature');
      this.validateTimestamp(timestamp);

      return `${local}@${domain}`;
    } else if (address.startsWith('SRS1')) {
      const match = SRS1_REGEX.exec(address);
      if (!match) throw new Error('Invalid SRS1');

      const [, hash, domain, local] = match;

      if (this.hash(domain, local) != hash)
        throw new TypeError('Bad signature');

      return `SRS0${local}@${domain}`;
    }

    return null;
  }
}
