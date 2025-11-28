/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Learn Mode Touch Device Behavior Tests
 * Tests the two-tap interaction pattern for touch devices
 */

import React from 'react';
import { render, fireEvent, waitFor, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { LearnModeOverlay } from '@dreadl0ck/netcap-ui/components';
import { LearnModeProvider, useLearnMode } from '@dreadl0ck/netcap-ui/contexts';

// Toggle component for testing
const LearnModeToggleButton = () => {
  const { toggleLearnMode, isLearnModeActive } = useLearnMode();
  return (
    <button onClick={toggleLearnMode} data-testid="learn-mode-toggle">
      {isLearnModeActive ? 'Deactivate' : 'Activate'} Learn Mode
    </button>
  );
};

// Mock component to provide a testable environment
const TestComponent = ({ children }: { children?: React.ReactNode }) => {
  return (
    <LearnModeProvider>
      <div>
        <LearnModeToggleButton />
        <LearnModeOverlay />
        <div data-testid="test-container">
          <button data-learn="This is button A" data-testid="button-a">
            Button A
          </button>
          <button data-learn="This is button B" data-testid="button-b">
            Button B
          </button>
          <button data-testid="button-no-learn">Button No Learn</button>
          {children}
        </div>
      </div>
    </LearnModeProvider>
  );
};

describe('LearnModeOverlay Touch Device Behavior', () => {
  let originalOntouchstart: any;
  let originalMaxTouchPoints: number;

  beforeEach(() => {
    // Mock touch device detection
    originalOntouchstart = window.ontouchstart;
    originalMaxTouchPoints = navigator.maxTouchPoints;
    
    // Make the environment appear as a touch device
    Object.defineProperty(window, 'ontouchstart', {
      configurable: true,
      value: {},
    });
    
    Object.defineProperty(navigator, 'maxTouchPoints', {
      configurable: true,
      writable: true,
      value: 5,
    });
  });

  afterEach(() => {
    // Restore original values
    if (originalOntouchstart === undefined) {
      delete (window as any).ontouchstart;
    } else {
      Object.defineProperty(window, 'ontouchstart', {
        configurable: true,
        value: originalOntouchstart,
      });
    }
    
    Object.defineProperty(navigator, 'maxTouchPoints', {
      configurable: true,
      writable: true,
      value: originalMaxTouchPoints,
    });
  });

  test('First tap on element with data-learn shows info and prevents default action', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');

    // Simulate first tap
    const clickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    
    const preventDefaultSpy = jest.spyOn(clickEvent, 'preventDefault');
    fireEvent(buttonA, clickEvent);

    // Info box should appear with the hint
    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // Default action should be prevented
    expect(preventDefaultSpy).toHaveBeenCalled();
  });

  test('Second tap on same element clears info and allows action', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');

    // First tap - show info
    const firstClickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    fireEvent(buttonA, firstClickEvent);

    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // Second tap on same element - should allow action
    const secondClickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    const preventDefaultSpy = jest.spyOn(secondClickEvent, 'preventDefault');
    fireEvent(buttonA, secondClickEvent);

    // Info should be cleared
    await waitFor(() => {
      expect(screen.queryByText('This is button A')).not.toBeInTheDocument();
    });

    // Default action should NOT be prevented (allow click through)
    expect(preventDefaultSpy).not.toHaveBeenCalled();
  });

  test('Second tap on different element with data-learn shows new info', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');
    const buttonB = getByTestId('button-b');

    // First tap on button A
    const firstClickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    fireEvent(buttonA, firstClickEvent);

    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // Tap on button B
    const secondClickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    const preventDefaultSpy = jest.spyOn(secondClickEvent, 'preventDefault');
    fireEvent(buttonB, secondClickEvent);

    // Should show info for button B
    await waitFor(() => {
      expect(screen.queryByText('This is button B')).toBeInTheDocument();
      expect(screen.queryByText('This is button A')).not.toBeInTheDocument();
    });

    // Should prevent default action
    expect(preventDefaultSpy).toHaveBeenCalled();
  });

  test('Tap on element without data-learn clears previous info and allows action', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');
    const buttonNoLearn = getByTestId('button-no-learn');

    // First tap on button A (with data-learn)
    const firstClickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    fireEvent(buttonA, firstClickEvent);

    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // Tap on button without data-learn
    const secondClickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    const preventDefaultSpy = jest.spyOn(secondClickEvent, 'preventDefault');
    fireEvent(buttonNoLearn, secondClickEvent);

    // Info should be cleared
    await waitFor(() => {
      expect(screen.queryByText('This is button A')).not.toBeInTheDocument();
    });

    // Default action should NOT be prevented (allow normal click)
    expect(preventDefaultSpy).not.toHaveBeenCalled();
  });

  test('Element highlighting works on touch devices', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');

    // Initial state - no highlight
    expect(buttonA.style.outline).toBe('');

    // First tap - should add highlight
    fireEvent.click(buttonA);

    // Check that info is shown (which confirms highlighting logic ran)
    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // The highlight should be applied (check immediately after interaction)
    expect(buttonA.style.outline).toContain('2px solid');

    // Second tap - should remove highlight and clear info
    fireEvent.click(buttonA);

    await waitFor(() => {
      expect(screen.queryByText('This is button A')).not.toBeInTheDocument();
      expect(buttonA.style.outline).toBe('');
    });
  });

  test('Highlight switches when tapping different elements', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');
    const buttonB = getByTestId('button-b');

    // Tap button A - should be highlighted and show info
    fireEvent.click(buttonA);

    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // Check that A is highlighted
    expect(buttonA.style.outline).toContain('2px solid');

    // Tap button B - highlight should switch to B
    fireEvent.click(buttonB);

    await waitFor(() => {
      expect(screen.queryByText('This is button B')).toBeInTheDocument();
      expect(screen.queryByText('This is button A')).not.toBeInTheDocument();
    });

    // Check that B is highlighted and A is not
    expect(buttonB.style.outline).toContain('2px solid');
    expect(buttonA.style.outline).toBe('');
  });

  test('Complete workflow: A -> B -> A -> click A', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');
    const buttonB = getByTestId('button-b');

    // Step 1: Tap A - show info for A
    fireEvent.click(buttonA);
    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // Step 2: Tap B - show info for B
    fireEvent.click(buttonB);
    await waitFor(() => {
      expect(screen.queryByText('This is button B')).toBeInTheDocument();
      expect(screen.queryByText('This is button A')).not.toBeInTheDocument();
    });

    // Step 3: Tap A again - show info for A
    fireEvent.click(buttonA);
    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
      expect(screen.queryByText('This is button B')).not.toBeInTheDocument();
    });

    // Step 4: Tap A again (second tap on same element) - should click through
    const finalClickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    const preventDefaultSpy = jest.spyOn(finalClickEvent, 'preventDefault');
    fireEvent(buttonA, finalClickEvent);

    await waitFor(() => {
      expect(screen.queryByText('This is button A')).not.toBeInTheDocument();
    });
    expect(preventDefaultSpy).not.toHaveBeenCalled();
  });

  test('TouchStart events are handled same as click events', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');

    // Use touchstart event instead of click
    const touchEvent = new TouchEvent('touchstart', {
      bubbles: true,
      cancelable: true,
    });
    const preventDefaultSpy = jest.spyOn(touchEvent, 'preventDefault');
    fireEvent(buttonA, touchEvent);

    // Info box should appear
    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // Default action should be prevented
    expect(preventDefaultSpy).toHaveBeenCalled();
  });

  test('Tapping element without data-learn when nothing is selected does not break', async () => {
    const { getByTestId } = render(<TestComponent />);
    const buttonNoLearn = getByTestId('button-no-learn');

    // Tap button without data-learn (no previous selection)
    const clickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    const preventDefaultSpy = jest.spyOn(clickEvent, 'preventDefault');
    fireEvent(buttonNoLearn, clickEvent);

    // Should not show any info
    await waitFor(() => {
      expect(screen.queryByText(/This is button/)).not.toBeInTheDocument();
    });

    // Should not prevent default
    expect(preventDefaultSpy).not.toHaveBeenCalled();
  });

  test('Close button clears state and allows next interaction to work correctly', async () => {
    const { getByTestId } = render(<TestComponent />);
    
    // Activate learn mode
    const toggleButton = getByTestId('learn-mode-toggle');
    fireEvent.click(toggleButton);
    
    const buttonA = getByTestId('button-a');

    // First tap - show info
    fireEvent.click(buttonA);
    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });

    // Click close button (find by the CloseIcon test id)
    const closeIcon = screen.getByTestId('CloseIcon');
    const closeButton = closeIcon.closest('button');
    expect(closeButton).not.toBeNull();
    fireEvent.click(closeButton!);

    await waitFor(() => {
      expect(screen.queryByText('This is button A')).not.toBeInTheDocument();
    });

    // Next tap on same button should show info again (not click through)
    const nextClickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    const preventDefaultSpy = jest.spyOn(nextClickEvent, 'preventDefault');
    fireEvent(buttonA, nextClickEvent);

    await waitFor(() => {
      expect(screen.queryByText('This is button A')).toBeInTheDocument();
    });
    expect(preventDefaultSpy).toHaveBeenCalled();
  });
});

describe('LearnModeOverlay Desktop Behavior', () => {
  beforeEach(() => {
    // Ensure we're not in touch device mode
    delete (window as any).ontouchstart;
    Object.defineProperty(navigator, 'maxTouchPoints', {
      configurable: true,
      writable: true,
      value: 0,
    });
  });

  test('Desktop mode does not use touch behavior', async () => {
    const { getByTestId } = render(<TestComponent />);
    const buttonA = getByTestId('button-a');

    // On desktop, clicking should not prevent default
    const clickEvent = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
    });
    const preventDefaultSpy = jest.spyOn(clickEvent, 'preventDefault');
    fireEvent(buttonA, clickEvent);

    // Should not prevent default on desktop
    expect(preventDefaultSpy).not.toHaveBeenCalled();
  });
});

