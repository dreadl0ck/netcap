# Web UI Learn Mode

## Overview

The Learn Mode is an interactive feature in the Netcap Web UI that helps users understand the functionality of different UI elements. When enabled, users can hover over or click on any element to see a contextual explanation displayed in a tooltip at the bottom right of the screen.

## How to Use

### Activating Learn Mode

1. Click the **graduation cap icon** (🎓) in the top navigation bar
2. The icon will turn cyan and pulse to indicate Learn Mode is active
3. A small cyan dot will appear on the icon to show active status

### Using Learn Mode

Once Learn Mode is activated:

**Desktop/Mouse:**
1. **Hover** over any UI element to see its information
2. **Click** on elements to see their tooltips
3. The element will be highlighted with a cyan outline
4. An info box will appear at the bottom right with:
   - The element's name as the title
   - A description of its functionality
5. Click the × button to dismiss the tooltip

**Touch Devices (Mobile/Tablet):**
1. **First tap** on an element shows the information tooltip
2. **Second tap** on the same element triggers its normal action
3. This allows you to learn about controls before activating them
4. Works correctly even when menus hide after selection

### Deactivating Learn Mode

1. Click the graduation cap icon again to exit Learn Mode
2. All tooltips will be automatically dismissed

## Supported Elements

Learn Mode currently provides contextual help for:

### Navigation Menu Items

- **Dashboard** - System status and metrics overview
- **Analyze** - PCAP file upload and processing
- **Interfaces** - Network interface selection for live capture
- **Hosts** - Discovered network hosts with geolocation
- **Devices** - Hardware devices and MAC address information
- **PCAPs** - Manage uploaded packet captures
- **Audit Records** - Protocol-specific traffic records
- **Explore** - Custom charts and visualizations
- **Visualize** - Protocol hierarchy flow diagrams
- **Logs** - System and processing logs
- **Errors** - Processing errors and troubleshooting
- **Rules** - Detection rule management
- **Rule Sets** - Organized rule collections
- **Alerts** - Security alerts from detection rules
- **Files** - Extracted files from network streams
- **Databases** - GeoIP and vulnerability databases
- **DPI** - Deep Packet Inspection configuration
- **Decoders** - Protocol decoder management
- **BPF Filters** - Berkeley Packet Filter expressions
- **Config** - System configuration settings

## For Developers

### Adding Learn Mode to Components

To add learn mode hints to your components, add the `data-learn` attribute to any element:

```tsx
<Button 
  data-learn="This button performs the analysis operation on the selected files."
  onClick={handleAnalyze}
>
  Analyze
</Button>
```

### Best Practices

1. **Keep descriptions short and concise** (aim for 1-2 sentences)
2. **Focus on what the element does**, not how to use it
3. **Use active voice** and start with a verb when possible
4. **Avoid technical jargon** unless necessary
5. **Be specific** about the element's purpose

### Context Provider

The learn mode functionality is managed through the `LearnModeContext`:

```tsx
import { useLearnMode } from '@/contexts/LearnModeContext';

function MyComponent() {
  const { isLearnModeActive, setCurrentHint } = useLearnMode();
  
  // Your component logic
}
```

### Custom Hints

For dynamic or computed hints, you can programmatically set hints:

```tsx
const { setCurrentHint } = useLearnMode();

const handleCustomInteraction = () => {
  setCurrentHint("Custom dynamic hint text");
};
```

## Technical Implementation

### Components

- **LearnModeContext** - React context for state management
- **LearnModeToggle** - Toggle button in the navigation bar
- **LearnModeOverlay** - Tooltip display component

### Features

- **Automatic detection** - Event listeners detect `data-learn` attributes
- **Smart titles** - Shows the actual element name instead of generic "Learn Mode"
- **Larger, readable text** - Increased font sizes for better readability
- **Visual feedback** - Cyan outline highlights interactive elements
- **Responsive positioning** - Tooltip fixed at bottom right (500px max width)
- **Fade animations** - Smooth transitions for tooltip display
- **Touch-friendly** - First tap shows info, second tap activates the control (properly handles synthetic click events)
- **Click to dismiss** - Manual close button on tooltips
- **Auto-cleanup** - Highlights fade after 2 seconds

## Future Enhancements

Potential improvements for Learn Mode:

- [ ] Multi-language support for tooltips
- [ ] Guided tours through common workflows
- [ ] Video tutorials embedded in tooltips
- [ ] Search functionality for hints
- [ ] User progress tracking
- [ ] Context-sensitive help based on user actions
- [ ] Tooltips for form fields and input elements
- [ ] Extended descriptions with "Learn More" links

