import { useState, useEffect, useRef } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { Loader2, Brain, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface RecommendationsPopupProps {
  isOpen: boolean;
  onClose: () => void;
  anomaly: any;
}

export function RecommendationsPopup({ isOpen, onClose, anomaly }: RecommendationsPopupProps) {
  const [recommendations, setRecommendations] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen && anomaly) {
      fetchRecommendations();
    }
    
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [isOpen, anomaly]);

  useEffect(() => {
    // Auto-scroll to bottom when new content arrives
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [recommendations]);

  const fetchRecommendations = () => {
    setIsLoading(true);
    setIsStreaming(true);
    setRecommendations('');
    setError(null);

    // Establish WebSocket connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    wsRef.current = new WebSocket(wsUrl);

    wsRef.current.onopen = () => {
      console.log('WebSocket connected for recommendations');
      // Send request for recommendations
      wsRef.current?.send(JSON.stringify({
        type: 'get_recommendations',
        anomalyId: anomaly.id
      }));
    };

    wsRef.current.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        
        switch (message.type) {
          case 'recommendation_chunk':
            setRecommendations(prev => prev + message.data);
            setIsLoading(false);
            break;
            
          case 'recommendation_complete':
            setIsStreaming(false);
            console.log('Recommendations complete');
            break;
            
          case 'error':
            setError(message.data);
            setIsLoading(false);
            setIsStreaming(false);
            break;
        }
      } catch (err) {
        console.error('WebSocket message parse error:', err);
        setError('Failed to parse recommendation response');
        setIsLoading(false);
        setIsStreaming(false);
      }
    };

    wsRef.current.onerror = (error) => {
      console.error('WebSocket error:', error);
      setError('Connection error. Please try again.');
      setIsLoading(false);
      setIsStreaming(false);
    };

    wsRef.current.onclose = () => {
      console.log('WebSocket closed');
      setIsStreaming(false);
    };
  };

  const formatRecommendationText = (text: string) => {
    // Split by common markdown headers and format
    const lines = text.split('\n');
    return lines.map((line, index) => {
      if (line.startsWith('###')) {
        return <h3 key={index} className="text-lg font-semibold mt-4 mb-2 text-blue-600 dark:text-blue-400">{line.replace('###', '').trim()}</h3>;
      }
      if (line.startsWith('##')) {
        return <h2 key={index} className="text-xl font-bold mt-4 mb-3 text-blue-700 dark:text-blue-300">{line.replace('##', '').trim()}</h2>;
      }
      if (line.startsWith('**') && line.endsWith('**')) {
        return <p key={index} className="font-semibold mt-2 mb-1">{line.replace(/\*\*/g, '')}</p>;
      }
      if (line.startsWith('•') || line.startsWith('-')) {
        return <li key={index} className="ml-4 mb-1">{line.replace(/^[•-]\s*/, '')}</li>;
      }
      if (line.trim()) {
        return <p key={index} className="mb-2">{line}</p>;
      }
      return <br key={index} />;
    });
  };

  const contextData = anomaly?.context_data ? JSON.parse(anomaly.context_data) : {};

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5 text-blue-600" />
            AI Troubleshooting Recommendations
          </DialogTitle>
        </DialogHeader>
        
        {/* Anomaly Details Card */}
        <Card className="mb-4">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Anomaly Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="font-medium">Type:</span>
                <p className="text-muted-foreground">{anomaly?.anomaly_type?.replace(/_/g, ' ')}</p>
              </div>
              <div>
                <span className="font-medium">Severity:</span>
                <Badge variant={
                  anomaly?.severity === 'critical' ? 'destructive' :
                  anomaly?.severity === 'high' ? 'secondary' :
                  'outline'
                } className="ml-1">
                  {anomaly?.severity}
                </Badge>
              </div>
              <div>
                <span className="font-medium">Confidence:</span>
                <p className="text-muted-foreground">{((anomaly?.confidence_score || 0) * 100).toFixed(1)}%</p>
              </div>
              <div>
                <span className="font-medium">Cell ID:</span>
                <p className="text-muted-foreground">{contextData.cell_id || 'Unknown'}</p>
              </div>
            </div>
            <div className="mt-3">
              <span className="font-medium">Description:</span>
              <p className="text-muted-foreground mt-1">{anomaly?.description}</p>
            </div>
          </CardContent>
        </Card>

        {/* Recommendations Content */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold">AI-Generated Recommendations</h3>
            {isStreaming && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Generating recommendations...
              </div>
            )}
          </div>

          <ScrollArea className="flex-1 border rounded-lg p-4" ref={scrollRef}>
            {isLoading && !recommendations && (
              <div className="flex items-center justify-center py-8">
                <div className="text-center">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-600" />
                  <p className="text-muted-foreground">Connecting to Mistral AI...</p>
                  <p className="text-sm text-muted-foreground mt-1">Generating troubleshooting recommendations</p>
                </div>
              </div>
            )}

            {error && (
              <div className="flex items-center gap-2 p-4 border border-red-200 rounded-lg bg-red-50 dark:bg-red-900/20">
                <AlertCircle className="h-5 w-5 text-red-600" />
                <div>
                  <p className="font-medium text-red-800 dark:text-red-200">Error generating recommendations</p>
                  <p className="text-sm text-red-600 dark:text-red-300 mt-1">{error}</p>
                </div>
              </div>
            )}

            {recommendations && (
              <div className="prose prose-sm max-w-none dark:prose-invert">
                {formatRecommendationText(recommendations)}
                {isStreaming && (
                  <span className="inline-block w-2 h-4 bg-blue-600 animate-pulse ml-1" />
                )}
              </div>
            )}
          </ScrollArea>

          <div className="flex justify-between items-center mt-4 pt-4 border-t">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Brain className="h-3 w-3" />
              Powered by Mistral AI at /tmp/llm_models
            </div>
            <div className="flex gap-2">
              {!isStreaming && recommendations && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={fetchRecommendations}
                  data-testid="button-refresh-recommendations"
                >
                  Refresh
                </Button>
              )}
              <Button
                variant="outline"
                onClick={onClose}
                data-testid="button-close-recommendations"
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}