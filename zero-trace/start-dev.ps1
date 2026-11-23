$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$python = Join-Path $backend ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
  throw "Backend virtual environment not found. Create it with: python -m venv backend\.venv"
}

Start-Process -FilePath $python -ArgumentList "manage.py","runserver","0.0.0.0:8000" -WorkingDirectory $backend -WindowStyle Normal
Start-Process -FilePath "cmd.exe" -ArgumentList "/c","npm.cmd run dev" -WorkingDirectory $frontend -WindowStyle Normal

Write-Output "ZeroTrace backend: http://127.0.0.1:8000/api/health/"
Write-Output "ZeroTrace frontend: http://localhost:5173"
