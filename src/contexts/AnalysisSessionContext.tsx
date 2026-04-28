import { createContext, useContext, useState, ReactNode } from 'react';

interface SessionMetadata {
  fileName?: string;
  fileHash?: string;
}

interface AnalysisSessionContextType {
  currentSessionId: string | null;
  setCurrentSessionId: (sessionId: string | null) => void;
  sessionMetadata: SessionMetadata | null;
  setSessionMetadata: (metadata: SessionMetadata | null) => void;
}

// Provide default values to prevent errors during development/hot reload
const defaultContextValue: AnalysisSessionContextType = {
  currentSessionId: null,
  setCurrentSessionId: () => {
    console.warn('setCurrentSessionId called outside provider');
  },
  sessionMetadata: null,
  setSessionMetadata: () => {
    console.warn('setSessionMetadata called outside provider');
  }
};

const AnalysisSessionContext = createContext<AnalysisSessionContextType>(defaultContextValue);

export const AnalysisSessionProvider = ({ children }: { children: ReactNode }) => {
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [sessionMetadata, setSessionMetadata] = useState<SessionMetadata | null>(null);

  return (
    <AnalysisSessionContext.Provider value={{ 
      currentSessionId, 
      setCurrentSessionId,
      sessionMetadata,
      setSessionMetadata
    }}>
      {children}
    </AnalysisSessionContext.Provider>
  );
};

export const useAnalysisSession = () => {
  const context = useContext(AnalysisSessionContext);
  // Context will always have a value (either from provider or default)
  return context;
};

