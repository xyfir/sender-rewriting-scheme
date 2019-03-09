Sender Rewriting Scheme for Node.

Written for and maintained by [Ptorx](https://ptorx.com), a proxy email service.

```ts
import { SRS } from 'sender-rewriting-scheme';

const srs = new SRS({
  separator: '=', // default
  secret: 'test1', // required
  maxAge: 30 // default
});

srs.forward('user@example.com', 'forward.com');
// SRS0=5884=RN=example.com=user@forward.com

srs.reverse('SRS0=5884=RN=example.com=user@forward.com');
// user@example.com
```
