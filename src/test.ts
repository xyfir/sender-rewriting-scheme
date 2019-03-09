import { SRS } from './srs';

global.Date.now = () => 1398772288249;

test('rewrite non-SRS', () => {
  const srs = new SRS({ secret: 'test1' });
  expect(srs.rewrite('me', 'samcday.com.au')).toBe(
    'SRS0=b4b4=Z5=samcday.com.au=me'
  );
});

test('rewrite SRS0 with guarded scheme', () => {
  const srs = new SRS({ secret: 'test1' });
  expect(srs.rewrite('SRS0=5840=Z5=samcday.com.au=me', 'forwarder.com')).toBe(
    'SRS1=b415=forwarder.com==5840=Z5=samcday.com.au=me'
  );
});

test('rewrite SRS1 with guarded scheme without change', () => {
  const srs = new SRS({ secret: 'test1' });
  expect(
    srs.rewrite(
      'SRS1=b415=forwarder.com==5840=Z5=samcday.com.au=me',
      'forwarder.com'
    )
  ).toBe('SRS1=b415=forwarder.com==5840=Z5=samcday.com.au=me');
});

test('rewrite SRS1 with guarded scheme with correct hash', () => {
  const srs = new SRS({ secret: 'test2' });
  expect(
    srs.rewrite(
      'SRS1=b415=forwarder.com==5840=Z5=samcday.com.au=me',
      'forwarder.com'
    )
  ).toBe('SRS1=a22d=forwarder.com==5840=Z5=samcday.com.au=me');
});

test('reverse SRS0', () => {
  const srs = new SRS({ secret: 'test1' });
  const reversed = srs.reverse('SRS0=b4b4=Z5=samcday.com.au=me');
  expect(reversed[0]).toBe('me');
  expect(reversed[1]).toBe('samcday.com.au');
});

test('reverse SRS1', () => {
  const srs = new SRS({ secret: 'test1' });
  const reversed = srs.reverse(
    'SRS1=b415=forwarder.com==5840=Z5=samcday.com.au=me'
  );
  expect(reversed[0]).toBe('SRS0=5840=Z5=samcday.com.au=me');
  expect(reversed[1]).toBe('forwarder.com');
});

test('reverse non-SRS', () => {
  const srs = new SRS({ secret: 'test1' });
  expect(srs.reverse('foo')).toBe(null);
});

test('reverse invalid local', () => {
  const srs = new SRS({ secret: 'test1' });
  expect(() => srs.reverse('SRS0=invalid')).toThrow(/Invalid SRS/);
});

test('reverse invalid hash', () => {
  const srs = new SRS({ secret: 'test2' });
  expect(() => srs.reverse('SRS0=5840=Z5=samcday.com.au=me')).toThrow(
    /Bad signature/
  );
});

test('reverse SRS1 with invalid signature', () => {
  const srs = new SRS({ secret: 'test1' });
  expect(() =>
    srs.reverse('SRS1=666f=forwarder.com==5840=Z5=samcday.com.au=me')
  ).toThrow(/Bad signature/);
});
