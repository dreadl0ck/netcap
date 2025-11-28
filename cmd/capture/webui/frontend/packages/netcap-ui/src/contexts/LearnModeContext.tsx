import { createContext, useContext, useState, useMemo, ReactNode } from 'react';

interface LearnModeContextType {
  isLearnModeActive: boolean;
  toggleLearnMode: () => void;
  currentHint: string | null;
  setCurrentHint: (hint: string | null) => void;
  currentElementTitle: string | null;
  setCurrentElementTitle: (title: string | null) => void;
  lastInteractedElement: HTMLElement | null;
  setLastInteractedElement: (element: HTMLElement | null) => void;
}

const LearnModeContext = createContext<LearnModeContextType | undefined>(undefined);

export function LearnModeProvider({ children }: { children: ReactNode }) {
  const [isLearnModeActive, setIsLearnModeActive] = useState(false);
  const [currentHint, setCurrentHint] = useState<string | null>(null);
  const [currentElementTitle, setCurrentElementTitle] = useState<string | null>(null);
  const [lastInteractedElement, setLastInteractedElement] = useState<HTMLElement | null>(null);

  const toggleLearnMode = () => {
    setIsLearnModeActive((prev) => !prev);
    if (isLearnModeActive) {
      setCurrentHint(null);
      setCurrentElementTitle(null);
      setLastInteractedElement(null);
    }
  };

  const value = useMemo(
    () => ({
      isLearnModeActive,
      toggleLearnMode,
      currentHint,
      setCurrentHint,
      currentElementTitle,
      setCurrentElementTitle,
      lastInteractedElement,
      setLastInteractedElement,
    }),
    [
      isLearnModeActive,
      currentHint,
      currentElementTitle,
      lastInteractedElement,
    ]
  );

  return (
    <LearnModeContext.Provider value={value}>
      {children}
    </LearnModeContext.Provider>
  );
}

export function useLearnMode() {
  const context = useContext(LearnModeContext);
  if (context === undefined) {
    throw new Error('useLearnMode must be used within a LearnModeProvider');
  }
  return context;
}


