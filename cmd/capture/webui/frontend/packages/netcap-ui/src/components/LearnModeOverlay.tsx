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

import { useEffect, useRef } from 'react';
import { Box, Paper, Typography, Fade, IconButton } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { useLearnMode } from '../contexts/LearnModeContext';

// Helper function to parse data-learn attribute into title and description
function parseLearnHint(hint: string): { title: string | null; description: string } {
  const colonIndex = hint.indexOf(':');
  
  if (colonIndex > 0 && colonIndex < hint.length - 1) {
    const potentialTitle = hint.substring(0, colonIndex).trim();
    const potentialDescription = hint.substring(colonIndex + 1).trim();
    
    if (potentialTitle.length <= 50 && potentialDescription.length > 0) {
      return {
        title: potentialTitle,
        description: potentialDescription,
      };
    }
  }
  
  return {
    title: null,
    description: hint,
  };
}

// Helper function to extract element name from the element
function getElementName(element: HTMLElement): string {
  const textContent = element.textContent?.trim() || '';
  
  const ariaLabel = element.getAttribute('aria-label');
  if (ariaLabel) return ariaLabel;
  
  const title = element.getAttribute('title');
  if (title) return title;
  
  if (element.tagName === 'BUTTON' || element.tagName === 'A') {
    return textContent.split('\n')[0].substring(0, 50);
  }
  
  const heading = element.querySelector('h1, h2, h3, h4, h5, h6');
  if (heading?.textContent) {
    return heading.textContent.trim();
  }
  
  const listItemText = element.querySelector('[class*="MuiListItemText-primary"]');
  if (listItemText?.textContent) {
    return listItemText.textContent.trim();
  }
  
  const words = textContent.split(/\s+/).filter(w => w.length > 0);
  return words.slice(0, 3).join(' ') || 'UI Element';
}

export function LearnModeOverlay() {
  const { 
    isLearnModeActive, 
    currentHint, 
    setCurrentHint, 
    currentElementTitle, 
    setCurrentElementTitle,
    lastInteractedElement,
    setLastInteractedElement,
  } = useLearnMode();

  const lastTouchTimeRef = useRef(0);
  const shouldBlockNextClickRef = useRef(false);

  useEffect(() => {
    if (!isLearnModeActive) {
      return;
    }

    let currentHighlightedElement: HTMLElement | null = null;
    const TOUCH_CLICK_DELAY = 500;

    const addHighlight = (element: HTMLElement) => {
      element.style.boxShadow = '0 0 0 2px #00bcd4, 0 0 8px rgba(0, 188, 212, 0.5)';
      element.style.position = element.style.position || 'relative';
      element.style.zIndex = '1';
    };

    const removeHighlight = (element: HTMLElement) => {
      element.style.boxShadow = '';
      element.style.zIndex = '';
    };

    if (lastInteractedElement && isLearnModeActive) {
      addHighlight(lastInteractedElement);
      currentHighlightedElement = lastInteractedElement;
    }

    const handleMouseOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      const learnElement = target.closest('[data-learn]') as HTMLElement;
      
      if (learnElement && learnElement !== currentHighlightedElement) {
        if (currentHighlightedElement) {
          removeHighlight(currentHighlightedElement);
        }
        
        const hint = learnElement.getAttribute('data-learn');
        if (hint) {
          const { title, description } = parseLearnHint(hint);
          setCurrentHint(description);
          setCurrentElementTitle(title || getElementName(learnElement));
          addHighlight(learnElement);
          currentHighlightedElement = learnElement;
        }
      }
    };

    const handleMouseOut = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      const learnElement = target.closest('[data-learn]') as HTMLElement;
      
      if (learnElement && learnElement === currentHighlightedElement) {
        removeHighlight(learnElement);
        currentHighlightedElement = null;
      }
    };

    const handleTouch = (e: TouchEvent) => {
      lastTouchTimeRef.current = Date.now();
      const target = e.target as HTMLElement;
      const learnElement = target.closest('[data-learn]') as HTMLElement;
      
      if (learnElement) {
        const hint = learnElement.getAttribute('data-learn');
        
        if (hint) {
          if (lastInteractedElement === learnElement) {
            setCurrentHint(null);
            setCurrentElementTitle(null);
            setLastInteractedElement(null);
            if (currentHighlightedElement === learnElement) {
              removeHighlight(learnElement);
              currentHighlightedElement = null;
            }
            shouldBlockNextClickRef.current = false;
            return;
          } else {
            if (currentHighlightedElement && currentHighlightedElement !== learnElement) {
              removeHighlight(currentHighlightedElement);
            }
            
            if (e.cancelable) {
              e.preventDefault();
            }
            e.stopPropagation();
            
            shouldBlockNextClickRef.current = true;
            
            const { title, description } = parseLearnHint(hint);
            setCurrentHint(description);
            setCurrentElementTitle(title || getElementName(learnElement));
            setLastInteractedElement(learnElement);
            
            addHighlight(learnElement);
            currentHighlightedElement = learnElement;
          }
        }
      } else {
        shouldBlockNextClickRef.current = false;
        
        if (lastInteractedElement) {
          setCurrentHint(null);
          setCurrentElementTitle(null);
          setLastInteractedElement(null);
          if (currentHighlightedElement) {
            removeHighlight(currentHighlightedElement);
            currentHighlightedElement = null;
          }
        }
      }
    };

    const handleClick = (e: MouseEvent) => {
      const timeSinceLastTouch = Date.now() - lastTouchTimeRef.current;
      if (timeSinceLastTouch < TOUCH_CLICK_DELAY) {
        if (shouldBlockNextClickRef.current) {
          e.preventDefault();
          e.stopPropagation();
          shouldBlockNextClickRef.current = false;
          return;
        }
        return;
      }
    };

    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

    if (!isTouchDevice) {
      document.addEventListener('mouseover', handleMouseOver);
      document.addEventListener('mouseout', handleMouseOut);
    }
    
    if (isTouchDevice) {
      document.addEventListener('touchstart', handleTouch, true);
    }
    
    document.addEventListener('click', handleClick, true);

    return () => {
      if (currentHighlightedElement) {
        currentHighlightedElement.style.boxShadow = '';
        currentHighlightedElement.style.zIndex = '';
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
          bottom: { xs: 80, sm: 24 },
          left: '50%',
          transform: 'translateX(-50%)',
          maxWidth: { xs: 'calc(100vw - 48px)', sm: 600 },
          minWidth: { xs: 'calc(100vw - 48px)', sm: 384 },
          p: { xs: 2, sm: 3 },
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
                fontSize: { xs: '1rem', sm: '1.32rem' },
              }}
            >
              {currentElementTitle || 'UI Element'}
            </Typography>
            <Typography 
              variant="body1" 
              sx={{ 
                lineHeight: 1.6,
                fontSize: { xs: '0.9rem', sm: '1.2rem' },
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

export default LearnModeOverlay;


