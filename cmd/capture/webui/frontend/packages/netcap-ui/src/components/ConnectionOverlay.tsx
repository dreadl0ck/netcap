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

import React from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import { keyframes } from '@mui/material/styles';

// Keyframe animations
const pulseGlow = keyframes`
  0%, 100% {
    filter: drop-shadow(0 0 20px rgba(0, 188, 212, 0.4)) 
            drop-shadow(0 0 40px rgba(0, 188, 212, 0.2));
  }
  50% {
    filter: drop-shadow(0 0 30px rgba(0, 188, 212, 0.6)) 
            drop-shadow(0 0 60px rgba(0, 188, 212, 0.4))
            drop-shadow(0 0 90px rgba(0, 188, 212, 0.2));
  }
`;

const fadeIn = keyframes`
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
`;

const slideUp = keyframes`
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const circuitPulse = keyframes`
  0%, 100% {
    opacity: 0.3;
  }
  50% {
    opacity: 0.6;
  }
`;

const scanLine = keyframes`
  0% {
    transform: translateY(-100%);
  }
  100% {
    transform: translateY(100vh);
  }
`;

export interface ConnectionOverlayProps {
  /** Whether the overlay is visible */
  visible: boolean;
  /** Loading message to display */
  message?: string;
  /** Sub-message for additional context */
  subMessage?: string;
  /** Custom logo src (defaults to /logo.png) */
  logoSrc?: string;
}

/**
 * ConnectionOverlay - A slick full-screen overlay with the NETCAP logo and loading spinner.
 * 
 * Shows during app startup and when the frontend cannot communicate with the backend.
 * Features a cyberpunk aesthetic with circuit pattern background and pulsing glow effects.
 */
export function ConnectionOverlay({ 
  visible, 
  message = 'Connecting to NETCAP...', 
  subMessage,
  logoSrc = '/logo.png',
}: ConnectionOverlayProps) {
  if (!visible) {
    return null;
  }

  return (
    <Box
      sx={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: 99999,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#0a0a0f',
        animation: `${fadeIn} 0.3s ease-out`,
        overflow: 'hidden',
      }}
    >
      {/* Animated background pattern */}
      <Box
        sx={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundImage: `
            radial-gradient(circle at 25% 25%, rgba(0, 188, 212, 0.03) 0%, transparent 50%),
            radial-gradient(circle at 75% 75%, rgba(0, 188, 212, 0.03) 0%, transparent 50%),
            linear-gradient(0deg, transparent 24%, rgba(0, 188, 212, 0.02) 25%, rgba(0, 188, 212, 0.02) 26%, transparent 27%, transparent 74%, rgba(0, 188, 212, 0.02) 75%, rgba(0, 188, 212, 0.02) 76%, transparent 77%),
            linear-gradient(90deg, transparent 24%, rgba(0, 188, 212, 0.02) 25%, rgba(0, 188, 212, 0.02) 26%, transparent 27%, transparent 74%, rgba(0, 188, 212, 0.02) 75%, rgba(0, 188, 212, 0.02) 76%, transparent 77%)
          `,
          backgroundSize: '100% 100%, 100% 100%, 80px 80px, 80px 80px',
          animation: `${circuitPulse} 4s ease-in-out infinite`,
          pointerEvents: 'none',
        }}
      />

      {/* Scan line effect */}
      <Box
        sx={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '2px',
          background: 'linear-gradient(90deg, transparent, rgba(0, 188, 212, 0.5), transparent)',
          animation: `${scanLine} 3s linear infinite`,
          pointerEvents: 'none',
        }}
      />

      {/* Content container */}
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 4,
          animation: `${slideUp} 0.5s ease-out`,
          zIndex: 1,
        }}
      >
        {/* Logo with glow effect */}
        <Box
          component="img"
          src={logoSrc}
          alt="NETCAP"
          sx={{
            width: { xs: '280px', sm: '400px', md: '500px' },
            height: 'auto',
            animation: `${pulseGlow} 3s ease-in-out infinite`,
            userSelect: 'none',
            pointerEvents: 'none',
          }}
        />

        {/* Spinner and message container */}
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 2,
            mt: 2,
          }}
        >
          {/* Custom styled spinner */}
          <Box
            sx={{
              position: 'relative',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {/* Outer ring */}
            <CircularProgress
              size={60}
              thickness={2}
              sx={{
                color: 'rgba(0, 188, 212, 0.2)',
              }}
              variant="determinate"
              value={100}
            />
            {/* Animated inner spinner */}
            <CircularProgress
              size={60}
              thickness={2}
              sx={{
                position: 'absolute',
                color: '#00bcd4',
                animationDuration: '1.2s',
              }}
            />
            {/* Center dot */}
            <Box
              sx={{
                position: 'absolute',
                width: 8,
                height: 8,
                borderRadius: '50%',
                backgroundColor: '#00bcd4',
                boxShadow: '0 0 10px rgba(0, 188, 212, 0.8), 0 0 20px rgba(0, 188, 212, 0.4)',
              }}
            />
          </Box>

          {/* Loading message */}
          <Typography
            variant="body1"
            sx={{
              color: '#00bcd4',
              fontWeight: 500,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              textAlign: 'center',
              textShadow: '0 0 10px rgba(0, 188, 212, 0.5)',
            }}
          >
            {message}
          </Typography>

          {/* Sub-message */}
          {subMessage && (
            <Typography
              variant="body2"
              sx={{
                color: 'rgba(255, 255, 255, 0.5)',
                textAlign: 'center',
                maxWidth: '400px',
              }}
            >
              {subMessage}
            </Typography>
          )}
        </Box>
      </Box>

      {/* Bottom gradient fade */}
      <Box
        sx={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          height: '100px',
          background: 'linear-gradient(to top, rgba(0, 188, 212, 0.05), transparent)',
          pointerEvents: 'none',
        }}
      />
    </Box>
  );
}

export default ConnectionOverlay;

