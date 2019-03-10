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

  forward(address: string, forwarder: string): string {
    const _address = address.split('@');
    const domain = _address.pop();
    const local = _address.join('@');
    const { separator: sep } = this.opt;

    let srs = '';
    if (local.startsWith('SRS0')) {
      const guarded = local.substring(4);
      srs = `SRS1${sep}${this.hash(
        domain,
        guarded
      )}${sep}${domain}${sep}${guarded}`;
    } else if (local.startsWith('SRS1')) {
      const m = SRS1_REGEX.exec(local);
      if (!m) throw new Error('Invalid SRS1 address');
      srs = `SRS1${sep}${this.hash(m[2], m[3])}=${m[2]}=${m[3]}`;
    } else {
      const timestamp = SRS.timestamp();
      srs = `SRS0${sep}${this.hash(
        timestamp,
        domain,
        local
      )}=${timestamp}=${domain}=${local}`;
    }

    return `${srs}@${forwarder}`;
  }

  reverse(address: string): string {
    address = address
      .split('@')
      .slice(0, -1)
      .join('@');

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
