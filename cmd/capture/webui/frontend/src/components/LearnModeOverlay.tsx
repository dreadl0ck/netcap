import { useEffect, useRef } from 'react';
import { Box, Paper, Typography, Fade, IconButton } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { useLearnMode } from '@/contexts/LearnModeContext';

// Helper function to extract element name from the element
function getElementName(element: HTMLElement): string {
  // Try to get text from the element or its children
  const textContent = element.textContent?.trim() || '';
  
  // Check for common aria-label or title attributes
  const ariaLabel = element.getAttribute('aria-label');
  if (ariaLabel) return ariaLabel;
  
  const title = element.getAttribute('title');
  if (title) return title;
  
  // For buttons and links, use their text content
  if (element.tagName === 'BUTTON' || element.tagName === 'A') {
    return textContent.split('\n')[0].substring(0, 50); // First line, max 50 chars
  }
  
  // Try to find a heading or label nearby
  const heading = element.querySelector('h1, h2, h3, h4, h5, h6');
  if (heading?.textContent) {
    return heading.textContent.trim();
  }
  
  // Check for ListItemText primary text (for navigation items)
  const listItemText = element.querySelector('[class*="MuiListItemText-primary"]');
  if (listItemText?.textContent) {
    return listItemText.textContent.trim();
  }
  
  // Return first few words of text content
  const words = textContent.split(/\s+/).filter(w => w.length > 0);
  return words.slice(0, 3).join(' ') || 'UI Element';
}

export default function LearnModeOverlay() {
  const { 
    isLearnModeActive, 
    currentHint, 
    setCurrentHint, 
    currentElementTitle, 
    setCurrentElementTitle,
    lastInteractedElement,
    setLastInteractedElement,
  } = useLearnMode();

  // Refs to track touch state across re-renders
  const lastTouchTimeRef = useRef(0);
  const shouldBlockNextClickRef = useRef(false);

  useEffect(() => {
    if (!isLearnModeActive) {
      return;
    }

    let currentHighlightedElement: HTMLElement | null = null;
    const TOUCH_CLICK_DELAY = 500; // 500ms window to ignore synthetic clicks after touch

    // Helper to add highlight to an element
    const addHighlight = (element: HTMLElement) => {
      element.style.outline = '2px solid #00bcd4';
      element.style.outlineOffset = '2px';
    };

    // Helper to remove highlight from an element
    const removeHighlight = (element: HTMLElement) => {
      element.style.outline = '';
      element.style.outlineOffset = '';
    };

    // Restore highlight if there is a last interacted element
    // This is necessary because re-renders (caused by state updates) run cleanup which removes the highlight
    if (lastInteractedElement && isLearnModeActive) {
      addHighlight(lastInteractedElement);
      currentHighlightedElement = lastInteractedElement;
    }

    const handleMouseOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      
      // Find the closest element with data-learn attribute
      const learnElement = target.closest('[data-learn]') as HTMLElement;
      
      if (learnElement && learnElement !== currentHighlightedElement) {
        // Remove highlight from previous element
        if (currentHighlightedElement) {
          removeHighlight(currentHighlightedElement);
        }
        
        const hint = learnElement.getAttribute('data-learn');
        if (hint) {
          setCurrentHint(hint);
          setCurrentElementTitle(getElementName(learnElement));
          // Add a highlight effect
          addHighlight(learnElement);
          currentHighlightedElement = learnElement;
        }
      }
    };

    const handleMouseOut = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      
      // Find the closest element with data-learn attribute
      const learnElement = target.closest('[data-learn]') as HTMLElement;
      
      if (learnElement && learnElement === currentHighlightedElement) {
        // Remove highlight when mouse leaves
        removeHighlight(learnElement);
        currentHighlightedElement = null;
      }
    };

    const handleTouch = (e: TouchEvent) => {
      lastTouchTimeRef.current = Date.now();
      const target = e.target as HTMLElement;
      
      // Find the closest element with data-learn attribute
      const learnElement = target.closest('[data-learn]') as HTMLElement;
      
      if (learnElement) {
        const hint = learnElement.getAttribute('data-learn');
        
        if (hint) {
          // On touch devices: first tap shows hint, second tap triggers action
          if (lastInteractedElement === learnElement) {
            // Second tap on same element - clear state, remove highlight, and let action proceed
            setCurrentHint(null);
            setCurrentElementTitle(null);
            setLastInteractedElement(null);
            if (currentHighlightedElement === learnElement) {
              removeHighlight(learnElement);
              currentHighlightedElement = null;
            }
            // Don't prevent default - let the action happen
            shouldBlockNextClickRef.current = false;
            return;
          } else {
            // First tap on this element or tap on a different element
            // Remove highlight from previous element
            if (currentHighlightedElement && currentHighlightedElement !== learnElement) {
              removeHighlight(currentHighlightedElement);
            }
            
            // Prevent default action and show hint
            // We try to prevent default here, but if it's a passive listener (some browsers),
            // it might fail. So we also set a flag to block the click in handleClick.
            if (e.cancelable) {
              e.preventDefault();
            }
            e.stopPropagation();
            
            shouldBlockNextClickRef.current = true;
            
            setCurrentHint(hint);
            setCurrentElementTitle(getElementName(learnElement));
            setLastInteractedElement(learnElement);
            
            // Add highlight to this element
            addHighlight(learnElement);
            currentHighlightedElement = learnElement;
          }
        }
      } else {
        // Tapped on an element without data-learn attribute
        shouldBlockNextClickRef.current = false;
        
        // If there was a previously interacted element, clear it
        if (lastInteractedElement) {
          setCurrentHint(null);
          setCurrentElementTitle(null);
          setLastInteractedElement(null);
          if (currentHighlightedElement) {
            removeHighlight(currentHighlightedElement);
            currentHighlightedElement = null;
          }
        }
        // Let the tap proceed normally (don't prevent default)
      }
    };

    const handleClick = (e: MouseEvent) => {
      // Check if this is a synthetic click from a touch event we already handled
      const timeSinceLastTouch = Date.now() - lastTouchTimeRef.current;
      if (timeSinceLastTouch < TOUCH_CLICK_DELAY) {
        // This is a synthetic click following a touch event
        
        // If we decided to block this click (First Tap case)
        if (shouldBlockNextClickRef.current) {
          e.preventDefault();
          e.stopPropagation();
          shouldBlockNextClickRef.current = false; // Reset flag
          return;
        }
        
        // Otherwise (Second Tap or No Learn Element), let it pass
        return;
      }
      
      // This is a real mouse click on a non-touch device
      // On desktop, clicks should work normally (hover shows hints, clicks work immediately)
      // So we don't prevent default for mouse clicks
    };

    // Check if this is a touch device
    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

    // Listen for hover on desktop (not applicable on pure touch devices)
    if (!isTouchDevice) {
    document.addEventListener('mouseover', handleMouseOver);
    document.addEventListener('mouseout', handleMouseOut);
    }
    
    // Listen for touch events on touch devices
    if (isTouchDevice) {
      document.addEventListener('touchstart', handleTouch, true);
    }
    
    // Always listen for click to handle synthetic clicks
    document.addEventListener('click', handleClick, true);

    return () => {
      // Clean up any remaining highlight
      if (currentHighlightedElement) {
        currentHighlightedElement.style.outline = '';
        currentHighlightedElement.style.outlineOffset = '';
      }
      document.removeEventListener('mouseover', handleMouseOver);
      document.removeEventListener('mouseout', handleMouseOut);
      document.removeEventListener('touchstart', handleTouch, true);
      document.removeEventListener('click', handleClick, true);
    };
  }, [isLearnModeActive, setCurrentHint, setCurrentElementTitle, lastInteractedElement, setLastInteractedElement]);

  if (!isLearnModeActive || !currentHint) {
    return null;
  }

  return (
    <Fade in={!!currentHint} timeout={150}>
      <Paper
        elevation={8}
        sx={{
          position: 'fixed',
          bottom: 24,
          left: '50%',
          transform: 'translateX(-50%)',
          maxWidth: 600,
          minWidth: 384,
          p: 3,
          zIndex: 9999,
          backgroundColor: 'rgba(0, 188, 212, 0.95)',
          color: 'white',
          borderRadius: 2,
          backdropFilter: 'blur(10px)',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
          <Box sx={{ flexGrow: 1 }}>
            <Typography 
              variant="h6" 
              sx={{ 
                fontWeight: 'bold', 
                mb: 1,
                fontSize: '1.32rem',
              }}
            >
              {currentElementTitle || 'UI Element'}
            </Typography>
            <Typography 
              variant="body1" 
              sx={{ 
                lineHeight: 1.6,
                fontSize: '1.2rem',
              }}
            >
              {currentHint}
            </Typography>
          </Box>
          <IconButton
            size="small"
            onClick={() => {
              setCurrentHint(null);
              setCurrentElementTitle(null);
              setLastInteractedElement(null);
            }}
            sx={{
              color: 'white',
              padding: 0.5,
              '&:hover': {
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
              },
            }}
          >
            <CloseIcon fontSize="small" />
          </IconButton>
        </Box>
      </Paper>
    </Fade>
  );
}

