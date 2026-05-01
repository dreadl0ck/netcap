/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useState, type MouseEvent } from 'react';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import AddIcon from '@mui/icons-material/Add';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import DashboardIcon from '@mui/icons-material/Dashboard';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DeleteIcon from '@mui/icons-material/Delete';
import DriveFileRenameOutlineIcon from '@mui/icons-material/DriveFileRenameOutline';

import type { Dashboard } from '../lib/api';

export const OVERVIEW_VIEW_ID = 'overview';

interface Props {
  dashboards: Dashboard[];
  activeId: string;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onRename: (d: Dashboard) => void;
  onDuplicate: (d: Dashboard) => void;
  onDelete: (d: Dashboard) => void;
}

export default function DashboardViewTabs({
  dashboards,
  activeId,
  onSelect,
  onCreate,
  onRename,
  onDuplicate,
  onDelete,
}: Props) {
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [menuTarget, setMenuTarget] = useState<Dashboard | null>(null);

  const openMenu = (event: MouseEvent<HTMLButtonElement>, d: Dashboard) => {
    event.stopPropagation();
    setMenuAnchor(event.currentTarget);
    setMenuTarget(d);
  };
  const closeMenu = () => {
    setMenuAnchor(null);
    setMenuTarget(null);
  };

  const handleTabChange = (_: any, value: string) => {
    if (value === '__new__') {
      onCreate();
      return;
    }
    onSelect(value);
  };

  return (
    <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
      <Tabs
        value={activeId}
        onChange={handleTabChange}
        variant="scrollable"
        scrollButtons="auto"
        allowScrollButtonsMobile
      >
        <Tab
          value={OVERVIEW_VIEW_ID}
          label="Overview"
          icon={<DashboardIcon fontSize="small" />}
          iconPosition="start"
          sx={{ minHeight: 48 }}
        />
        {dashboards.map((d) => (
          <Tab
            key={d.id}
            value={d.id}
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <span>{d.name}</span>
                {!d.builtin && (
                  <Tooltip title="View options">
                    <IconButton
                      size="small"
                      onClick={(e) => openMenu(e, d)}
                      sx={{ ml: 0.5, p: 0.25 }}
                    >
                      <MoreVertIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                )}
              </Box>
            }
            sx={{ minHeight: 48, textTransform: 'none' }}
          />
        ))}
        <Tab
          value="__new__"
          label="New"
          icon={<AddIcon fontSize="small" />}
          iconPosition="start"
          sx={{ minHeight: 48, textTransform: 'none', opacity: 0.85 }}
        />
      </Tabs>

      <Menu anchorEl={menuAnchor} open={Boolean(menuAnchor)} onClose={closeMenu}>
        <MenuItem
          onClick={() => {
            if (menuTarget) onRename(menuTarget);
            closeMenu();
          }}
        >
          <ListItemIcon><DriveFileRenameOutlineIcon fontSize="small" /></ListItemIcon>
          <ListItemText>Rename</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (menuTarget) onDuplicate(menuTarget);
            closeMenu();
          }}
        >
          <ListItemIcon><ContentCopyIcon fontSize="small" /></ListItemIcon>
          <ListItemText>Duplicate</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (menuTarget) onDelete(menuTarget);
            closeMenu();
          }}
        >
          <ListItemIcon><DeleteIcon fontSize="small" color="error" /></ListItemIcon>
          <ListItemText sx={{ color: 'error.main' }}>Delete</ListItemText>
        </MenuItem>
      </Menu>
    </Box>
  );
}
