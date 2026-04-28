/**
 * ConnectionStatus — shows a banner when the browser goes offline.
 * No Firebase dependency; pure browser navigator.onLine tracking.
 */
import { useState, useEffect } from 'react';
import { Alert, AlertDescription } from './ui/alert';
import { Wifi, WifiOff } from 'lucide-react';

export const ConnectionStatus = () => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [showStatus, setShowStatus] = useState(false);

  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      setShowStatus(true);
      setTimeout(() => setShowStatus(false), 3000);
    };

    const handleOffline = () => {
      setIsOnline(false);
      setShowStatus(true);
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  if (!showStatus) return null;

  return (
    <div className="fixed top-4 right-4 z-50 max-w-sm">
      <Alert className={isOnline ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'}>
        <div className="flex items-center gap-2">
          {isOnline
            ? <Wifi className="h-4 w-4 text-green-600" />
            : <WifiOff className="h-4 w-4 text-red-600" />
          }
          <AlertDescription className={isOnline ? 'text-green-800' : 'text-red-800'}>
            {isOnline ? 'Network connection restored' : 'Network offline — backend still reachable via localhost'}
          </AlertDescription>
        </div>
      </Alert>
    </div>
  );
};

