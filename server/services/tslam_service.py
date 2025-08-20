#!/usr/bin/env python3

import sys
import json
import time
import os
import requests
import socket
from datetime import datetime
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

class TSLAMService:
    def __init__(self):
        self.model_path = os.getenv('TSLAM_MODEL_PATH', '/home/users/praveen.joe/TSLAM-4B')
        self.model = None
        self.tokenizer = None
        self.load_model()

    def load_model(self):
        """Load TSLAM 4B model optimized for Tesla P40"""
        try:
            print("Loading TSLAM 4B model from /home/users/praveen.joe/TSLAM-4B...", file=sys.stderr)

            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            # Load model with Tesla P40 optimizations
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype=torch.float16,  # Optimized for Tesla P40
                device_map="cuda:0" if torch.cuda.is_available() else "cpu",
                load_in_4bit=True,  # 4-bit quantization for memory efficiency
                max_memory={"0": "22GB"} if torch.cuda.is_available() else None,  # Leave 2GB for other processes
                trust_remote_code=True
            )
            print("TSLAM model loaded successfully on Tesla P40", file=sys.stderr)

        except Exception as e:
            print(f"Error loading TSLAM model: {e}", file=sys.stderr)
            print("Model loading failed - no AI recommendations will be available", file=sys.stderr)
            self.model = None
            self.tokenizer = None

    def get_troubleshooting_prompt(self, anomaly_id, description):
        """Generate troubleshooting prompt for TSLAM model"""
        prompt = f"""You are an expert network engineer specializing in 5G network troubleshooting and anomaly analysis. 

Anomaly ID: {anomaly_id}
Description: {description}

Please provide a comprehensive analysis and troubleshooting guide for this network anomaly. Include:

1. **Root Cause Analysis**: What likely caused this issue?
2. **Immediate Actions**: Steps to take right now to mitigate the problem
3. **Detailed Investigation**: How to gather more information and diagnose the issue
4. **Resolution Steps**: Step-by-step instructions to fix the problem
5. **Prevention Measures**: How to prevent this issue in the future

Focus on practical, actionable recommendations that a network engineer can implement immediately.

Analysis:"""

        return prompt

    def generate_streaming_response(self, anomaly_id, description):
        """Generate real-time streaming response from TSLAM model"""
        if self.model is None or self.tokenizer is None:
            print("ERROR: TSLAM model not loaded - unable to generate AI recommendations", file=sys.stderr)
            return

        try:
            prompt = self.get_troubleshooting_prompt(anomaly_id, description)
            print(f"Generating AI recommendations for: {description}", file=sys.stderr)

            # Tokenize input for Tesla P40
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
            if torch.cuda.is_available():
                inputs = {k: v.to('cuda:0') for k, v in inputs.items()}

            # Generate streaming response token by token
            with torch.no_grad():
                generated_ids = inputs['input_ids']

                for step in range(800):  # Max 800 tokens for comprehensive analysis
                    # Generate next token
                    outputs = self.model(
                        input_ids=generated_ids,
                        attention_mask=torch.ones_like(generated_ids),
                        use_cache=True
                    )

                    # Get logits for next token prediction
                    next_token_logits = outputs.logits[:, -1, :] / 0.7  # Temperature scaling

                    # Apply top-p sampling for better quality
                    sorted_logits, sorted_indices = torch.sort(next_token_logits, descending=True)
                    cumulative_probs = torch.cumsum(torch.softmax(sorted_logits, dim=-1), dim=-1)
                    sorted_indices_to_remove = cumulative_probs > 0.9
                    sorted_indices_to_remove[..., 1:] = sorted_indices_to_remove[..., :-1].clone()
                    sorted_indices_to_remove[..., 0] = 0
                    indices_to_remove = sorted_indices[sorted_indices_to_remove]
                    next_token_logits[:, indices_to_remove] = -float('Inf')

                    # Sample next token
                    next_token_probs = torch.softmax(next_token_logits, dim=-1)
                    next_token = torch.multinomial(next_token_probs, num_samples=1)

                    # Decode and output token
                    token_text = self.tokenizer.decode(next_token[0], skip_special_tokens=True)
                    print(token_text, end='', flush=True)

                    # Append token to generated sequence
                    generated_ids = torch.cat([generated_ids, next_token], dim=-1)

                    # Stop if EOS token or end of analysis
                    if next_token.item() == self.tokenizer.eos_token_id:
                        break

                    # Streaming delay for real-time effect
                    time.sleep(0.02)  # 50 tokens per second

        except Exception as e:
            print(f"TSLAM inference error: {e}", file=sys.stderr)
            print("AI recommendation generation failed", file=sys.stderr)

    def generate_fallback_message(self, anomaly_id, description):
        """Generate error message when TSLAM model is not available"""
        error_message = f"""## TSLAM Model Not Available

**Anomaly ID:** {anomaly_id}
**Description:** {description}

**Error:** The TSLAM telecommunications AI model could not be loaded from /home/users/praveen.joe/TSLAM-4B

**To resolve this issue:**
1. Verify the model files are properly downloaded
2. Check GPU availability (Tesla P40 expected)
3. Ensure all dependencies are installed (transformers, torch, bitsandbytes)
4. Review server logs for detailed error information

**Technical Requirements:**
- Model Path: /home/users/praveen.joe/TSLAM-4B
- GPU Memory: 24GB Tesla P40 with 4-bit quantization
- Dependencies: torch, transformers, bitsandbytes

Please contact your system administrator to resolve the model loading issue.
"""

        # Stream the error message
        words = error_message.split()
        for word in words:
            print(word + ' ', end='', flush=True)
            time.sleep(0.05)

def main():
    if len(sys.argv) != 3:
        print("Usage: python tslam_service.py <anomaly_id> <description>", file=sys.stderr)
        sys.exit(1)

    anomaly_id = sys.argv[1]
    description = sys.argv[2]

    service = TSLAMService()
    service.generate_streaming_response(anomaly_id, description)

if __name__ == "__main__":
    main()