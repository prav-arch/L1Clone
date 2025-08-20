
import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Brain, TrendingUp, TrendingDown, Info, X, Copy, Download } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { Anomaly } from "@shared/schema";

interface ExplainableAIModalProps {
  isOpen: boolean;
  onClose: () => void;
  anomaly: Anomaly | null;
}

interface ExplanationData {
  model_explanations: {
    [key: string]: {
      feature_contributions: { [key: string]: number };
      top_positive_features: Array<{ feature: string; value: number; impact: number }>;
      top_negative_features: Array<{ feature: string; value: number; impact: number }>;
      confidence: number;
      decision: string;
    };
  };
  human_explanation: string;
  feature_descriptions: { [key: string]: string };
  overall_confidence: number;
  model_agreement: number;
}

export function ExplainableAIModal({ isOpen, onClose, anomaly }: ExplainableAIModalProps) {
  const [explanationData, setExplanationData] = useState<ExplanationData | null>(null);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (isOpen && anomaly) {
      fetchExplanation();
    }
  }, [isOpen, anomaly]);

  const fetchExplanation = async () => {
    if (!anomaly) return;
    
    setLoading(true);
    try {
      const response = await fetch(`/api/anomalies/${anomaly.id}/explanation`);
      if (response.ok) {
        const data = await response.json();
        setExplanationData(data);
      } else {
        toast({
          title: "Error",
          description: "Failed to fetch anomaly explanation",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error('Error fetching explanation:', error);
      toast({
        title: "Error",
        description: "Failed to fetch anomaly explanation",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async () => {
    if (!explanationData) return;
    
    const textContent = `
Anomaly Explanation - ${anomaly?.description}

Overall Confidence: ${explanationData.overall_confidence.toFixed(3)}
Model Agreement: ${explanationData.model_agreement}/4 algorithms

${explanationData.human_explanation}

Detailed Model Analysis:
${Object.entries(explanationData.model_explanations).map(([model, data]) => `
${model.replace('_', ' ').toUpperCase()}:
- Decision: ${data.decision}
- Confidence: ${data.confidence.toFixed(3)}
- Top Contributing Features:
${data.top_positive_features.map(f => `  • ${f.feature}: ${f.value.toFixed(3)} (Impact: ${f.impact.toFixed(3)})`).join('\n')}
`).join('\n')}
    `.trim();

    try {
      await navigator.clipboard.writeText(textContent);
      toast({
        title: "Copied to clipboard",
        description: "Explanation details copied successfully.",
      });
    } catch (error) {
      toast({
        title: "Copy failed",
        description: "Unable to copy to clipboard.",
        variant: "destructive",
      });
    }
  };

  const exportExplanation = () => {
    if (!explanationData || !anomaly) return;
    
    const textContent = `
Anomaly Explanation Report
Generated: ${new Date().toLocaleString()}

Anomaly ID: ${anomaly.id}
Type: ${anomaly.type || anomaly.anomaly_type}
Description: ${anomaly.description}
Timestamp: ${new Date(anomaly.timestamp).toLocaleString()}

Overall Analysis:
- Confidence Score: ${explanationData.overall_confidence.toFixed(3)}
- Model Agreement: ${explanationData.model_agreement}/4 algorithms
- Severity: ${anomaly.severity}

Human-Readable Explanation:
${explanationData.human_explanation}

Detailed Model Analysis:
${Object.entries(explanationData.model_explanations).map(([model, data]) => `
${model.replace('_', ' ').toUpperCase()} Model:
- Decision: ${data.decision}
- Confidence: ${data.confidence.toFixed(3)}

Top Contributing Features:
${data.top_positive_features.map(f => `  • ${explanationData.feature_descriptions[f.feature] || f.feature}: ${f.value.toFixed(3)} (Impact: ${f.impact.toFixed(3)})`).join('\n')}

${data.top_negative_features.length > 0 ? `
Factors Against Anomaly:
${data.top_negative_features.map(f => `  • ${explanationData.feature_descriptions[f.feature] || f.feature}: ${f.value.toFixed(3)} (Impact: ${Math.abs(f.impact).toFixed(3)})`).join('\n')}
` : ''}
`).join('\n')}
    `.trim();

    const blob = new Blob([textContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `anomaly-explanation-${anomaly.id}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return "bg-red-500";
    if (confidence >= 0.6) return "bg-orange-500";
    if (confidence >= 0.4) return "bg-yellow-500";
    return "bg-green-500";
  };

  const getImpactIcon = (impact: number) => {
    return impact > 0 ? <TrendingUp className="w-4 h-4 text-red-500" /> : <TrendingDown className="w-4 h-4 text-green-500" />;
  };

  if (!anomaly) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-6xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Brain className="h-5 w-5 text-purple-600" />
              Explainable AI Analysis
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={copyToClipboard}
                disabled={!explanationData}
              >
                <Copy className="h-4 w-4 mr-1" />
                Copy
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={exportExplanation}
                disabled={!explanationData}
              >
                <Download className="h-4 w-4 mr-1" />
                Export
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={onClose}
                className="h-8 w-8 p-0"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="max-h-[70vh] overflow-y-auto space-y-4">
          {/* Anomaly Overview */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center gap-2">
                <Info className="h-5 w-5 text-blue-600" />
                Anomaly Overview
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="font-medium">Type:</span>
                  <p className="text-muted-foreground">{anomaly.type || anomaly.anomaly_type}</p>
                </div>
                <div>
                  <span className="font-medium">Severity:</span>
                  <Badge variant={anomaly.severity === 'high' ? 'destructive' : 'secondary'}>
                    {anomaly.severity}
                  </Badge>
                </div>
                <div>
                  <span className="font-medium">Packet:</span>
                  <p className="text-muted-foreground">#{anomaly.packet_number || 'N/A'}</p>
                </div>
                <div>
                  <span className="font-medium">Source:</span>
                  <p className="text-muted-foreground">{anomaly.source_file}</p>
                </div>
              </div>
              <div>
                <span className="font-medium">Description:</span>
                <p className="text-sm text-muted-foreground mt-1">{anomaly.description}</p>
              </div>
            </CardContent>
          </Card>

          {loading ? (
            <Card>
              <CardContent className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600"></div>
                <span className="ml-3">Loading AI explanation...</span>
              </CardContent>
            </Card>
          ) : explanationData ? (
            <>
              {/* Overall Analysis */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Overall Analysis</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Overall Confidence</span>
                        <span>{(explanationData.overall_confidence * 100).toFixed(1)}%</span>
                      </div>
                      <Progress 
                        value={explanationData.overall_confidence * 100} 
                        className="h-2"
                      />
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Model Agreement</span>
                        <span>{explanationData.model_agreement}/4 algorithms</span>
                      </div>
                      <Progress 
                        value={(explanationData.model_agreement / 4) * 100} 
                        className="h-2"
                      />
                    </div>
                  </div>
                  
                  <div className="bg-blue-50 p-4 rounded-lg">
                    <h4 className="font-medium text-blue-800 mb-2">Human-Readable Explanation:</h4>
                    <p className="text-sm text-blue-700 whitespace-pre-line">
                      {explanationData.human_explanation}
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Model-by-Model Analysis */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(explanationData.model_explanations).map(([modelName, modelData]) => (
                  <Card key={modelName}>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base flex items-center justify-between">
                        <span>{modelName.replace('_', ' ').toUpperCase()}</span>
                        <Badge variant={modelData.decision === 'ANOMALY' ? 'destructive' : 'secondary'}>
                          {modelData.decision}
                        </Badge>
                      </CardTitle>
                      <div className="flex justify-between text-sm">
                        <span>Confidence:</span>
                        <span>{(modelData.confidence * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelData.confidence * 100} className="h-1" />
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {modelData.top_positive_features.length > 0 && (
                        <div>
                          <h5 className="text-sm font-medium mb-2 text-red-700">
                            Top Anomaly Indicators:
                          </h5>
                          <div className="space-y-2">
                            {modelData.top_positive_features.slice(0, 3).map((feature, idx) => (
                              <div key={idx} className="flex items-center justify-between text-xs">
                                <div className="flex items-center gap-1">
                                  {getImpactIcon(feature.impact)}
                                  <span className="truncate max-w-32">
                                    {explanationData.feature_descriptions[feature.feature] || feature.feature}
                                  </span>
                                </div>
                                <div className="text-right">
                                  <div>Value: {feature.value.toFixed(3)}</div>
                                  <div className="text-red-600">Impact: {feature.impact.toFixed(3)}</div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {modelData.top_negative_features.length > 0 && (
                        <div>
                          <Separator className="my-2" />
                          <h5 className="text-sm font-medium mb-2 text-green-700">
                            Factors Against Anomaly:
                          </h5>
                          <div className="space-y-2">
                            {modelData.top_negative_features.slice(0, 2).map((feature, idx) => (
                              <div key={idx} className="flex items-center justify-between text-xs">
                                <div className="flex items-center gap-1">
                                  {getImpactIcon(feature.impact)}
                                  <span className="truncate max-w-32">
                                    {explanationData.feature_descriptions[feature.feature] || feature.feature}
                                  </span>
                                </div>
                                <div className="text-right">
                                  <div>Value: {feature.value.toFixed(3)}</div>
                                  <div className="text-green-600">Impact: {Math.abs(feature.impact).toFixed(3)}</div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </>
          ) : (
            <Card>
              <CardContent className="flex items-center justify-center py-12 text-muted-foreground">
                <Brain className="h-8 w-8 mr-3 opacity-50" />
                <span>No explanation data available for this anomaly</span>
              </CardContent>
            </Card>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
