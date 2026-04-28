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

import BottomNavigation from '@mui/material/BottomNavigation';
import BottomNavigationAction from '@mui/material/BottomNavigationAction';
import Paper from '@mui/material/Paper';
import DashboardIcon from '@mui/icons-material/Dashboard';
import StorageIcon from '@mui/icons-material/Storage';
import DevicesIcon from '@mui/icons-material/Devices';
import NotificationsActiveIcon from '@mui/icons-material/NotificationsActive';
import MoreHorizIcon from '@mui/icons-material/MoreHoriz';
import { useNetcapRouter } from '../hooks/useNetcapRouter';

interface MobileBottomNavProps {
  onMoreClick: () => void;
}

const NAV_ITEMS = [
  { label: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { label: 'Records', icon: <StorageIcon />, path: '/records' },
  { label: 'Hosts', icon: <DevicesIcon />, path: '/hosts' },
  { label: 'Alerts', icon: <NotificationsActiveIcon />, path: '/alerts' },
] as const;

export default function MobileBottomNav({ onMoreClick }: MobileBottomNavProps) {
  const router = useNetcapRouter();

  const activeIndex = NAV_ITEMS.findIndex(item => router.isActive(item.path));
  // If no nav item matches, use -1 (nothing highlighted); "More" will not be highlighted
  const value = activeIndex >= 0 ? activeIndex : -1;

  return (
    <Paper
      sx={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 1100,
        display: { xs: 'block', md: 'none' },
      }}
      elevation={8}
    >
      <BottomNavigation
        value={value}
        onChange={(_event, newValue: number) => {
          // Only navigate for the 4 main tabs; "More" (index 4) opens the drawer via its onClick
          if (newValue < NAV_ITEMS.length) {
            router.push(NAV_ITEMS[newValue].path);
          }
        }}
        showLabels
        sx={{
          '& .MuiBottomNavigationAction-root': {
            minWidth: 0,
            px: 0.5,
          },
          '& .MuiBottomNavigationAction-label': {
            fontSize: '0.65rem',
            '&.Mui-selected': {
              fontSize: '0.7rem',
            },
          },
        }}
      >
        {NAV_ITEMS.map(item => (
          <BottomNavigationAction
            key={item.path}
            label={item.label}
            icon={item.icon}
          />
        ))}
        <BottomNavigationAction
          label="More"
          icon={<MoreHorizIcon />}
          onClick={(e) => {
            e.preventDefault();
            onMoreClick();
          }}
        />
      </BottomNavigation>
    </Paper>
  );
}
