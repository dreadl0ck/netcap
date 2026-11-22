import { afterEach, beforeEach, expect, vi } from 'vitest';
import * as matchers from '@testing-library/jest-dom/matchers';

expect.extend(matchers);
let requests: string[];
beforeEach(() => {
  requests = [];
  vi.stubGlobal('fetch', (input: unknown) => {
    requests.push(String(input));
    return Promise.reject(new Error('Unexpected network in ui-mocked presentation test'));
  });
});
afterEach(() => { expect(requests, 'presentation tests must use their declared API/bridge fakes').toEqual([]); vi.unstubAllGlobals(); });
