# Autocomplete Unit Tests

This directory contains comprehensive unit tests for the audit records filter autocomplete functionality.

## Test Files

### 1. `autocomplete-logic.test.ts`
Pure logic tests that verify the autocomplete suggestion and insertion algorithms without React components.

**What it tests:**
- Context-aware suggestion generation
- Field name filtering
- Operator suggestions
- Value suggestions with proper quoting
- Logical operator suggestions
- Complete expression building chains
- Edge cases and special characters

**Run with:**
```bash
pnpm test autocomplete-logic
```

### 2. `audit-autocomplete.test.tsx`
Full component integration tests that simulate user interactions with the autocomplete component.

**What it tests:**
- TAB key completes first suggestion when dropdown is open
- TAB key inserts first suggestion when dropdown is closed
- ENTER key executes filter when dropdown is closed
- ENTER key selects suggestion when dropdown is open
- CMD+ENTER executes filter immediately (bypasses dropdown)
- CTRL+ENTER executes filter immediately (Windows/Linux)
- Multiple TAB presses chain completions correctly
- ESC key closes dropdown without side effects
- Context-aware suggestions adapt to input position

**Run with:**
```bash
pnpm test audit-autocomplete
```

## Running Tests

### Install Dependencies
```bash
cd cmd/capture/webui/frontend
pnpm install
```

### Run All Tests
```bash
pnpm test
```

### Run Tests in Watch Mode
```bash
pnpm run test:watch
```

### Run Tests with Coverage
```bash
pnpm run test:coverage
```

### Run Specific Test File
```bash
pnpm test -- autocomplete-logic
pnpm test -- audit-autocomplete
```

## Key Behavior Requirements

### TAB Key Behavior
1. **When dropdown is open:** Selects the highlighted/first option
2. **When dropdown is closed:** Opens dropdown and inserts first available suggestion
3. **After completion:** Reopens dropdown with new contextual suggestions
4. **Prevents default:** TAB should never navigate away from the input field when dialog is open

### ENTER Key Behavior
1. **When dropdown is open:** Selects the highlighted suggestion (does NOT execute filter)
2. **When dropdown is closed:** Executes the filter query
3. **With CMD/CTRL modifier:** Always executes filter immediately, regardless of dropdown state

### Context-Aware Suggestions
1. **Empty input:** Shows all field names
2. **Partial field name:** Filters field names
3. **After field name:** Suggests operators (==, !=, <, >, etc.)
4. **After operator:** Suggests field values (with proper quoting for strings)
5. **After complete value:** Suggests logical operators (&&, ||)
6. **After logical operator:** Shows field names again

## Test Coverage Goals

- ✅ Key event handling (TAB, ENTER, ESC)
- ✅ Suggestion generation logic
- ✅ Value insertion logic
- ✅ Context detection
- ✅ Type-aware quoting (numeric vs string)
- ✅ Chain completion flows
- ✅ Edge cases (empty input, whitespace, special chars)

## Debugging Failed Tests

If tests fail, check:

1. **Dependencies installed:** Run `pnpm install` in the frontend directory
2. **Jest configuration:** Ensure `jest.config.js` and `jest.setup.js` are present
3. **Mock implementations:** Check that API mocks in test files match actual API
4. **Component changes:** If audit.tsx was modified, update test expectations
5. **Browser APIs:** Ensure all browser APIs used are mocked in jest.setup.js

## Adding New Tests

When adding new autocomplete features, add tests for:

1. The pure logic function (in `autocomplete-logic.test.ts`)
2. The user interaction flow (in `audit-autocomplete.test.tsx`)
3. Edge cases and error conditions
4. Accessibility features (keyboard navigation, screen readers)

## Known Issues & Limitations

- **MUI Autocomplete testing:** MUI components can be tricky to test. We may need to access internal state
- **Timing issues:** Some tests use `waitFor` to handle async updates
- **Real DOM events:** Some keyboard events may behave differently in jest-dom vs real browser
- **Focus management:** TAB behavior requires careful focus management testing

## Future Improvements

- [ ] Add E2E tests with Playwright or Cypress for real browser testing
- [ ] Add accessibility tests (ARIA attributes, keyboard navigation)
- [ ] Add performance tests (suggestion generation speed)
- [ ] Add visual regression tests (dropdown appearance)
- [ ] Test with screen readers

