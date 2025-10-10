import { useState, useEffect } from 'react';
import { Alert, AlertDescription } from './ui/alert';
import { Button } from './ui/button';
import { Wifi, WifiOff, RefreshCw } from 'lucide-react';
import { connectionManager } from '@/config/firebase';

export const ConnectionStatus = () => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [isConnecting, setIsConnecting] = useState(false);
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

  const handleRetryConnection = async () => {
    setIsConnecting(true);
    try {
      const success = await connectionManager.retryConnection();
      if (success) {
        setIsOnline(true);
        setShowStatus(true);
        setTimeout(() => setShowStatus(false), 3000);
      }
    } catch (error) {
      console.error('Failed to reconnect:', error);
    } finally {
      setIsConnecting(false);
    }
  };

  if (!showStatus && isOnline) {
    return null;
  }

  return (
    <div className="fixed top-4 right-4 z-50 max-w-sm">
      <Alert className={isOnline ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'}>
        <div className="flex items-center gap-2">
          {isOnline ? (
            <Wifi className="h-4 w-4 text-green-600" />
          ) : (
            <WifiOff className="h-4 w-4 text-red-600" />
          )}
          <AlertDescription className={isOnline ? 'text-green-800' : 'text-red-800'}>
            {isOnline ? 'Connection restored' : 'Connection lost - Some features may be unavailable'}
          </AlertDescription>
        </div>
        {!isOnline && (
          <div className="mt-2">
            <Button
              size="sm"
              variant="outline"
              onClick={handleRetryConnection}
              disabled={isConnecting}
              className="h-8"
            >
              {isConnecting ? (
                <RefreshCw className="h-3 w-3 animate-spin mr-1" />
              ) : (
                <RefreshCw className="h-3 w-3 mr-1" />
              )}
              Retry Connection
            </Button>
          </div>
        )}
      </Alert>
    </div>
  );
};

