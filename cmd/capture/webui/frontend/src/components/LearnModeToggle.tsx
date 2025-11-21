import { IconButton, Tooltip, Box } from '@mui/material';
import SchoolIcon from '@mui/icons-material/School';
import { useLearnMode } from '@/contexts/LearnModeContext';

export default function LearnModeToggle() {
  const { isLearnModeActive, toggleLearnMode } = useLearnMode();

  return (
    <Tooltip title={isLearnModeActive ? 'Exit Learn Mode' : 'Enter Learn Mode'}>
      <Box sx={{ position: 'relative' }}>
        <IconButton
          color="inherit"
          onClick={toggleLearnMode}
          sx={{
            color: isLearnModeActive ? '#00bcd4' : 'inherit',
            backgroundColor: isLearnModeActive ? 'rgba(0, 188, 212, 0.1)' : 'transparent',
            '&:hover': {
              backgroundColor: isLearnModeActive ? 'rgba(0, 188, 212, 0.2)' : 'rgba(255, 255, 255, 0.1)',
            },
            transition: 'all 0.3s',
          }}
        >
          <SchoolIcon />
        </IconButton>
        {isLearnModeActive && (
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              right: 0,
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: '#00bcd4',
              animation: 'pulse 2s infinite',
              '@keyframes pulse': {
                '0%, 100%': {
                  opacity: 1,
                },
                '50%': {
                  opacity: 0.5,
                },
              },
            }}
          />
        )}
      </Box>
    </Tooltip>
  );
}

