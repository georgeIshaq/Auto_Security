# Auto Security - GitHub Repository Scanner

A full-stack application that integrates with GitHub to scan repositories for security vulnerabilities and automatically create pull requests with fixes.

## Features

- **GitHub Integration**: Connect to GitHub using personal access tokens
- **Repository Selection**: Browse and select repositories from your GitHub account
- **Security Scanning**: Automated vulnerability detection (simulated)
- **Auto-Remediation**: Automatic creation of pull requests with security fixes
- **Modern UI**: Built with Next.js and shadcn/ui components

## Architecture

- **Backend**: Flask API (`app.py`) with GitHub integration using PyGithub
- **Frontend**: Next.js application with TypeScript and Tailwind CSS
- **API Endpoints**:
  - `GET /health` - Health check
  - `GET /api/repositories` - List GitHub repositories
  - `GET /api/repositories/<owner>/<repo>` - Get repository details

## Prerequisites

- Python 3.8+
- Node.js 18+
- GitHub Personal Access Token

## Setup Instructions

### 1. Backend Setup

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Set your GitHub token:
```bash
export GITHUB_TOKEN=your_github_token_here
```

3. Start the Flask server:
```bash
python app.py
```

The API will be available at `http://localhost:5000`

### 2. Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

### 3. Testing the Integration

Run the test script to verify everything is working:

```bash
python test_api.py
```

## Usage

1. **Connect to GitHub**: 
   - Enter your GitHub Personal Access Token
   - Optionally specify a username/organization to browse their repositories
   - Click "Connect GitHub"

2. **Select Repository**:
   - Choose a repository from the dropdown
   - The list shows repository name, language, privacy status, and star count

3. **Start Security Scan**:
   - Click "Start Security Scan" to begin the automated process
   - Watch the progress as the system scans for vulnerabilities
   - View the results including discovered issues and generated pull requests

## API Documentation

### Health Check
```http
GET /health
```

### List Repositories
```http
GET /api/repositories?token=YOUR_TOKEN&username=USERNAME&per_page=30&page=1
```

**Query Parameters:**
- `token` (required): GitHub personal access token
- `username` (optional): Specific username/organization
- `org` (optional): Organization name
- `type` (optional): Repository type (all, owner, public, private, member)
- `sort` (optional): Sort field (created, updated, pushed, full_name)
- `direction` (optional): Sort direction (asc, desc)
- `per_page` (optional): Results per page (max 100)
- `page` (optional): Page number

### Get Repository Details
```http
GET /api/repositories/{owner}/{repo}?token=YOUR_TOKEN&detailed=true
```

## Environment Variables

- `GITHUB_TOKEN`: GitHub personal access token
- `PORT`: Flask server port (default: 5000)
- `FLASK_DEBUG`: Enable debug mode (default: False)
- `NEXT_PUBLIC_API_URL`: Frontend API URL (default: http://localhost:5000)

## Development

### Backend Development
- The Flask app uses PyGithub for GitHub API integration
- Error handling includes proper HTTP status codes
- CORS is enabled for frontend integration

### Frontend Development
- Built with Next.js 14 and TypeScript
- Uses shadcn/ui components for consistent design
- Implements proper error handling and loading states
- Responsive design for mobile and desktop

## Security Notes

- GitHub tokens are handled securely and not stored
- All API calls use HTTPS in production
- Input validation is implemented on both frontend and backend

## Troubleshooting

1. **"GitHub service not initialized"**: Make sure GITHUB_TOKEN is set
2. **"Failed to fetch repositories"**: Check your token permissions and network connection
3. **CORS errors**: Ensure the Flask server is running and CORS is enabled
4. **Frontend not loading**: Check that both servers are running on correct ports

## License

MIT License - see LICENSE file for details
