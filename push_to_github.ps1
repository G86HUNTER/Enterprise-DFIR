# PowerShell script to push the Enterprise‑DFIR project to GitHub
# ---------------------------------------------------------------
# This script assumes the environment variable GITHUB_TOKEN contains a
# personal‑access token with the "repo" scope. Do NOT paste the token
# in this file – it will be read from the variable at runtime.
# ---------------------------------------------------------------
$repoUrl = "https://github.com/G86HUNTER/Enterprise-DFIR.git"
$branchName = "main"

# Abort on any error
$ErrorActionPreference = "Stop"

# Initialise repository if needed
if (-not (Test-Path ".git")) {
    Write-Host "Initializing new Git repository..."
    git init
    git config user.name "DFIR Deploy Bot"
    git config user.email "dfir-deploy@example.com"
} else {
    Write-Host "Git repository already exists."
}

# Create .gitignore if missing
$gitignore = ".gitignore"
if (-not (Test-Path $gitignore)) {
    @"
# Byte‑compiled / cached Python files
__pycache__/
*.pyc
*.pyo

# Virtual environment
.venv/
venv/
env/
ENV/

# SQLite database – will be stored on a persistent disk in production
data/*.db

# Uploaded evidence (kept on persistent storage)
uploads/

# OS‑specific files
.DS_Store
Thumbs.db

# IDE / editor folders
.vscode/
.idea/
"@ | Set-Content -Path $gitignore -Encoding UTF8
    Write-Host ".gitignore created."
}

# Stage everything and commit (if there are changes)
git add -A
if (git diff --cached --quiet) {
    Write-Host "No changes to commit."
} else {
    git commit -m "Initial commit – Enterprise DFIR project (auto‑generated)"
}

# Set or update remote origin
if (git remote | Select-String "^origin") {
    git remote set-url origin $repoUrl
} else {
    git remote add origin $repoUrl
}

# Verify token is present
if (-not $env:GITHUB_TOKEN) {
    Write-Error "GITHUB_TOKEN environment variable not set. Please set it to a personal‑access token with repo scope."
}

# Push using the token via an extra HTTP header (Git's credential helper)
$authHeader = "Authorization: token $env:GITHUB_TOKEN"

git -c http.extraHeader="$authHeader" push -u origin $branchName

Write-Host "Push completed successfully."
