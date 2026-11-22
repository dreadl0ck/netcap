import { fireEvent, render } from '@testing-library/react';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { expect, it, vi } from 'vitest';
import SyntaxHighlightedInput from './SyntaxHighlightedInput';
import { appearanceTokens } from '../lib/appearance';

it('recolors an editor in place without losing selection, focus or original expression', () => {
  const onChange = vi.fn();
  const text = 'Length > 42\n&& Protocol == "TCP"';
  const readText = (node: Node): string => node.nodeName === 'BR' ? '\n' : node.nodeType === Node.TEXT_NODE ? node.textContent ?? '' : [...node.childNodes].map(readText).join('');
  Object.defineProperty(HTMLElement.prototype, 'innerText', { configurable: true, get() { return readText(this); } });
  const view = (mode: 'dark' | 'light') => <ThemeProvider theme={createTheme({ palette: { mode } })}><SyntaxHighlightedInput syntaxType="filter" value={text} onChange={onChange} multiline /></ThemeProvider>;
  const { container, rerender } = render(view('dark'));
  const editor = container.querySelector('[contenteditable]') as HTMLElement;
  fireEvent.focus(editor);
  editor.focus();
  const spans = editor.querySelectorAll('span');
  const range = document.createRange(); range.setStart(spans[0].firstChild!, 1); range.setEnd(spans[0].firstChild!, 4);
  window.getSelection()!.removeAllRanges(); window.getSelection()!.addRange(range);
  rerender(view('light'));
  expect(readText(editor)).toBe(text);
  expect(editor.querySelectorAll('span')[0]).toBe(spans[0]);
  expect(window.getSelection()!.toString()).toBe('eng');
  expect(document.activeElement).toBe(editor);
  expect(spans[0].style.color).toBe('rgb(7, 89, 133)');
  expect(onChange).not.toHaveBeenCalled();
  expect(appearanceTokens('light').syntax.key).toBe('#075985');
  delete (HTMLElement.prototype as unknown as { innerText?: string }).innerText;
});
