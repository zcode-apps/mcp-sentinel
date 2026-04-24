#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_cmd git
require_cmd npm
require_cmd node

PACKAGE_NAME="$(node -p "require('./package.json').name")"
PACKAGE_VERSION="$(node -p "require('./package.json').version")"
CURRENT_BRANCH="$(git branch --show-current)"
TAG_NAME="v${PACKAGE_VERSION}"

echo "Deploying ${PACKAGE_NAME}@${PACKAGE_VERSION}"

if [[ -z "$CURRENT_BRANCH" ]]; then
  echo "Could not determine current git branch." >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Working tree is not clean. Commit or stash your changes before deploying." >&2
  exit 1
fi

if [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo "Untracked files detected. Commit or remove them before deploying." >&2
  exit 1
fi

if ! npm whoami >/dev/null 2>&1; then
  echo "npm authentication missing. Run: npm login" >&2
  exit 1
fi

echo "Installing dependencies..."
npm install

echo "Building package..."
npm run build

echo "Previewing npm package contents..."
npm pack --dry-run >/dev/null

echo "Pushing ${CURRENT_BRANCH} to origin..."
git push origin "$CURRENT_BRANCH"

if [[ -n "${GITHUB_REMOTE_URL:-}" ]]; then
  if git remote get-url github >/dev/null 2>&1; then
    git remote set-url github "$GITHUB_REMOTE_URL"
  else
    git remote add github "$GITHUB_REMOTE_URL"
  fi
fi

if git remote get-url github >/dev/null 2>&1; then
  echo "Pushing ${CURRENT_BRANCH} to github..."
  git push github "$CURRENT_BRANCH"
else
  echo "No github remote configured. Skipping GitHub push."
  echo "Set GITHUB_REMOTE_URL to enable it."
fi

if git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
  echo "Git tag ${TAG_NAME} already exists."
else
  echo "Creating git tag ${TAG_NAME}..."
  git tag -a "$TAG_NAME" -m "$TAG_NAME"
fi

echo "Pushing tag ${TAG_NAME} to origin..."
git push origin "$TAG_NAME"

if git remote get-url github >/dev/null 2>&1; then
  echo "Pushing tag ${TAG_NAME} to github..."
  git push github "$TAG_NAME"
fi

echo "Publishing ${PACKAGE_NAME}@${PACKAGE_VERSION} to npm..."
npm publish --access public

echo
echo "Deploy completed."
echo "Package: ${PACKAGE_NAME}@${PACKAGE_VERSION}"
echo "Branch: ${CURRENT_BRANCH}"
echo "Tag: ${TAG_NAME}"
