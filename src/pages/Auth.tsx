import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/contexts/AuthContext';
import { toast } from 'sonner';

const Auth = () => {
  const { signInWithGoogle, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = (location.state as any)?.from?.pathname || '/';

  useEffect(() => {
    // Redirect if already authenticated
    if (!loading && localStorage.getItem('isAuthenticated')) {
      navigate(from, { replace: true });
    }
  }, [loading, navigate, from]);

  const handleGoogleSignIn = async () => {
    try {
      await signInWithGoogle();
      toast.success('Signed in with Google successfully!');
      navigate(from, { replace: true });
    } catch (error: any) {
      console.error('Google auth error:', error);
      toast.error(error.message || 'Google sign-in failed');
    }
  };

  return (
    <main className="min-h-screen bg-gradient-to-br from-background via-background-subtle to-background-muted flex items-center justify-center p-4">
      <div className="w-full max-w-md animate-fade-in">
        <Card className="backdrop-blur-sm bg-card/80 border-primary/20 shadow-glow-primary">
          <CardHeader className="space-y-1 text-center">
            <div className="mb-4">
              <div className="w-16 h-16 mx-auto mb-4">
                <img 
                  src="/logo.png" 
                  alt="Malware Analysis Platform" 
                  className="w-full h-full object-contain"
                />
              </div>
            </div>
            <CardTitle className="text-2xl font-semibold bg-gradient-primary bg-clip-text text-transparent text-white">
              Welcome to Agora Platform
            </CardTitle>
          </CardHeader>

          <CardContent className="space-y-6">
            <div className="text-center">
              <p className="text-muted-foreground mb-6">
                Secure access to advanced malware analysis tools with enterprise-grade security
              </p>
            </div>

            <Button
              onClick={handleGoogleSignIn}
              disabled={loading}
              className="w-full bg-white hover:bg-gray-50 text-gray-900 border border-gray-300 transition-all duration-200 h-12 text-base font-medium"
            >
              {loading ? (
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-5 h-5 border-2 border-gray-300 border-t-gray-900 rounded-full animate-spin" />
                  <span>Signing in...</span>
                </div>
              ) : (
                <div className="flex items-center justify-center space-x-3">
                  <svg className="w-5 h-5" viewBox="0 0 24 24">
                    <path
                      fill="#4285F4"
                      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                    />
                    <path
                      fill="#34A853"
                      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                    />
                    <path
                      fill="#FBBC05"
                      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                    />
                    <path
                      fill="#EA4335"
                      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                    />
                  </svg>
                  <span>Sign in with Google</span>
                </div>
              )}
            </Button>

            <div className="text-center text-xs text-muted-foreground">
              By signing in, you agree to your Google account terms and our privacy policy
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  );
};

export default Auth;