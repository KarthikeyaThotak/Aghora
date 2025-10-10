import { useState, useRef, useEffect } from "react";
import { Play, Pause, Volume2, VolumeX, Maximize, RotateCcw, FastForward } from "lucide-react";
import { Button } from "./ui/button";
import { Slider } from "./ui/slider";

export const VideoPlayer = () => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(300); // 5 minutes mock duration
  const [volume, setVolume] = useState(1);
  const [isMuted, setIsMuted] = useState(false);
  const [showControls, setShowControls] = useState(true);
  const videoRef = useRef<HTMLVideoElement>(null);
  const hideControlsTimeout = useRef<NodeJS.Timeout>();

  useEffect(() => {
    const interval = setInterval(() => {
      if (isPlaying) {
        setCurrentTime(prev => Math.min(prev + 1, duration));
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [isPlaying, duration]);

  useEffect(() => {
    if (currentTime >= duration) {
      setIsPlaying(false);
      setCurrentTime(0);
    }
  }, [currentTime, duration]);

  const handlePlayPause = () => {
    const newPlayingState = !isPlaying;
    setIsPlaying(newPlayingState);
    
    // Show controls when toggling play/pause
    setShowControls(true);
    
    // Reset auto-hide timer
    if (hideControlsTimeout.current) {
      clearTimeout(hideControlsTimeout.current);
    }
    
    // Hide controls after 3 seconds if playing
    if (newPlayingState) {
      hideControlsTimeout.current = setTimeout(() => {
        setShowControls(false);
      }, 3000);
    }
  };

  const handleSeek = (value: number[]) => {
    setCurrentTime(value[0]);
  };

  const handleVolumeChange = (value: number[]) => {
    setVolume(value[0]);
    setIsMuted(value[0] === 0);
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const handleMouseMove = () => {
    setShowControls(true);
    if (hideControlsTimeout.current) {
      clearTimeout(hideControlsTimeout.current);
    }
    hideControlsTimeout.current = setTimeout(() => {
      if (isPlaying) {
        setShowControls(false);
      }
    }, 3000);
  };

  const handleFullscreen = () => {
    if (videoRef.current && videoRef.current.parentElement) {
      if (document.fullscreenElement) {
        document.exitFullscreen();
      } else {
        videoRef.current.parentElement.requestFullscreen();
      }
    }
  };

  return (
    <div 
      className="h-full bg-background relative overflow-hidden"
      onMouseMove={handleMouseMove}
      onMouseLeave={() => isPlaying && setShowControls(false)}
    >
      {/* Video Container */}
      <div className="relative h-full flex items-center justify-center bg-gradient-to-br from-background-secondary to-background-tertiary">
        {/* Mock Video Display */}
        <div className="relative w-full h-full max-w-6xl max-h-[80vh] bg-black rounded-lg overflow-hidden shadow-glow-primary">
          <video
            ref={videoRef}
            className="w-full h-full object-contain"
            poster="/api/placeholder/800/600"
          />
          
          {/* Video Overlay - Analysis Information */}
          <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-black/30">
            {/* Video Title Overlay */}
            <div className="absolute top-4 left-4 right-4">
              <div className="bg-background-secondary/90 backdrop-blur-sm rounded-lg p-3 border border-primary/20">
                <h3 className="text-lg font-semibold text-foreground mb-1">Malware Execution Recording</h3>
                <p className="text-sm text-muted-foreground">Sample: suspicious_payload.exe | Session ID: MSA-2024-0115-001</p>
                <div className="flex items-center gap-4 mt-2 text-xs">
                  <span className="flex items-center gap-1">
                    <div className="w-2 h-2 rounded-full bg-destructive animate-pulse"></div>
                    Recording Active
                  </span>
                  <span className="text-muted-foreground">VM Environment: Windows 10 x64</span>
                </div>
              </div>
            </div>

            {/* Analysis Markers */}
            <div className="absolute right-4 top-20 space-y-2">
              <div className="bg-destructive/20 border border-destructive rounded-lg p-2 text-xs">
                <div className="text-destructive font-medium">Critical Event</div>
                <div className="text-destructive-foreground">Registry modification detected</div>
              </div>
              <div className="bg-primary/20 border border-primary rounded-lg p-2 text-xs">
                <div className="text-primary font-medium">Network Activity</div>
                <div className="text-primary-foreground">Outbound connection initiated</div>
              </div>
            </div>
          </div>

          {/* Play Button Overlay */}
          {!isPlaying && (
            <div className="absolute inset-0 flex items-center justify-center">
              <Button
                onClick={handlePlayPause}
                variant="ghost"
                size="icon"
                className="w-20 h-20 rounded-full bg-primary/20 hover:bg-primary/30 backdrop-blur-sm border-2 border-primary/40"
              >
                <Play className="w-10 h-10 text-primary ml-1" />
              </Button>
            </div>
          )}

          {/* Click to pause overlay when playing */}
          {isPlaying && (
            <div 
              className="absolute inset-0 cursor-pointer"
              onClick={handlePlayPause}
            />
          )}
        </div>

        {/* Controls */}
        <div
          className={`absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/90 via-black/70 to-transparent p-6 transition-all duration-300 ${
            showControls ? "translate-y-0 opacity-100" : "translate-y-full opacity-0"
          }`}
        >
          {/* Progress Bar */}
          <div className="mb-4">
            <Slider
              value={[currentTime]}
              max={duration}
              step={1}
              onValueChange={handleSeek}
              className="w-full"
            />
            <div className="flex justify-between text-xs text-muted-foreground mt-1">
              <span>{formatTime(currentTime)}</span>
              <span>{formatTime(duration)}</span>
            </div>
          </div>

          {/* Control Buttons */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {/* Play/Pause */}
              <Button 
                onClick={handlePlayPause} 
                variant="ghost" 
                size="icon"
                className="hover:bg-primary/20"
              >
                {isPlaying ? (
                  <Pause className="w-5 h-5 text-primary" />
                ) : (
                  <Play className="w-5 h-5 text-primary" />
                )}
              </Button>

              {/* Rewind */}
              <Button 
                onClick={() => setCurrentTime(Math.max(0, currentTime - 10))}
                variant="ghost" 
                size="icon"
              >
                <RotateCcw className="w-4 h-4" />
              </Button>

              {/* Fast Forward */}
              <Button 
                onClick={() => setCurrentTime(Math.min(duration, currentTime + 10))}
                variant="ghost" 
                size="icon"
              >
                <FastForward className="w-4 h-4" />
              </Button>

              {/* Volume */}
              <div className="flex items-center gap-2 ml-4">
                <Button
                  onClick={() => setIsMuted(!isMuted)}
                  variant="ghost"
                  size="icon"
                >
                  {isMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
                </Button>
                <div className="w-20">
                  <Slider
                    value={[isMuted ? 0 : volume]}
                    max={1}
                    step={0.1}
                    onValueChange={handleVolumeChange}
                    className="w-full"
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {/* Playback Speed */}
              <select className="bg-background-secondary border border-border rounded px-2 py-1 text-sm text-foreground">
                <option value="0.5">0.5x</option>
                <option value="1" selected>1x</option>
                <option value="1.5">1.5x</option>
                <option value="2">2x</option>
              </select>

              {/* Fullscreen */}
              <Button onClick={handleFullscreen} variant="ghost" size="icon">
                <Maximize className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};