
FROM node:18-alpine

# Install Python and required packages
RUN apk add --no-cache python3 py3-pip python3-dev gcc musl-dev

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY requirements_mistral.txt ./

# Install Node.js dependencies
RUN npm ci --only=production

# Install Python dependencies
RUN pip3 install -r requirements_mistral.txt

# Copy application code
COPY . .

# Build the application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Change ownership of the app directory
RUN chown -R nextjs:nodejs /app

USER nextjs

EXPOSE 5000

CMD ["npm", "start"]
