#!/usr/bin/env bash
# release.sh — bump version, tag, compute SHA256, update Homebrew formula
#
# Usage:   ./release.sh <version>
# Example: ./release.sh 0.10.0
#
# Assumes:
#   - All code changes and CHANGES file are committed and on master
#   - Working tree is clean
#   - Remote is 'origin'
#   - Tap repo lives at TAP_DIR (default: sibling directory homebrew-airsnare)

set -euo pipefail

VERSION="${1:?Usage: $0 <version>}"
TAG="v${VERSION}"
YEAR=$(date +%Y)
REPO_URL="https://github.com/rtulke/airsnare"
TARBALL_URL="${REPO_URL}/archive/refs/tags/${TAG}.tar.gz"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAP_DIR="${TAP_DIR:-${SCRIPT_DIR}/../homebrew-airsnare}"

# -----------------------------------------------------------------------
# Preflight checks
# -----------------------------------------------------------------------

if [[ -n "$(git status --porcelain)" ]]; then
    echo "Error: working tree is dirty — commit or stash changes first." >&2
    exit 1
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "${CURRENT_BRANCH}" != "master" ]]; then
    echo "Error: not on master (currently on '${CURRENT_BRANCH}')." >&2
    exit 1
fi

if git rev-parse "${TAG}" >/dev/null 2>&1; then
    echo "Error: tag ${TAG} already exists." >&2
    exit 1
fi

if [[ ! -d "${TAP_DIR}/.git" ]]; then
    echo "Error: tap repo not found at '${TAP_DIR}'." >&2
    echo "  Clone or create it first, or set TAP_DIR=/path/to/homebrew-airsnare" >&2
    exit 1
fi

if [[ -n "$(git -C "${TAP_DIR}" status --porcelain)" ]]; then
    echo "Error: tap repo at '${TAP_DIR}' has uncommitted changes." >&2
    exit 1
fi

# -----------------------------------------------------------------------
# 1. Update src/release.h
# -----------------------------------------------------------------------

echo "→ Updating src/release.h  (version=${VERSION}, year=${YEAR})"
sed -i '' "s/#define ZZ_VERSION \"[^\"]*\"/#define ZZ_VERSION \"${VERSION}\"/" src/release.h
sed -i '' "s/#define ZZ_YEAR \"[^\"]*\"/#define ZZ_YEAR \"${YEAR}\"/"         src/release.h

# -----------------------------------------------------------------------
# 2. Commit version bump
# -----------------------------------------------------------------------

git add src/release.h
git commit -m "Bump version to ${VERSION}"

# -----------------------------------------------------------------------
# 3. Create tag and push branch + tag
# -----------------------------------------------------------------------

echo "→ Creating tag ${TAG} and pushing"
git tag "${TAG}"
git push origin master "${TAG}"

# -----------------------------------------------------------------------
# 4. Compute SHA256 (retry until GitHub serves the tarball)
# -----------------------------------------------------------------------

echo "→ Waiting for GitHub tarball (up to 60 s)..."
SHA256=""
TMPFILE=$(mktemp)

for i in $(seq 1 12); do
    if curl -sfL -o "${TMPFILE}" "${TARBALL_URL}"; then
        SHA256=$(shasum -a 256 "${TMPFILE}" | awk '{print $1}')
        break
    fi
    echo "  attempt ${i}/12 — not yet available, retrying in 5 s..."
    sleep 5
done

rm -f "${TMPFILE}"

if [[ -z "${SHA256}" ]]; then
    echo "" >&2
    echo "Error: could not download tarball after 12 attempts." >&2
    echo "Compute SHA256 manually and update Formula/airsnare.rb:" >&2
    echo "  curl -sL ${TARBALL_URL} | shasum -a 256" >&2
    exit 1
fi

echo "  SHA256: ${SHA256}"

# -----------------------------------------------------------------------
# 5. Update Homebrew formula
# -----------------------------------------------------------------------

echo "→ Updating Formula/airsnare.rb"
sed -i '' "s|url \"[^\"]*\"|url \"${TARBALL_URL}\"|"   Formula/airsnare.rb
sed -i '' "s|sha256 \"[^\"]*\"|sha256 \"${SHA256}\"|"  Formula/airsnare.rb

# -----------------------------------------------------------------------
# 6. Commit and push updated formula
# -----------------------------------------------------------------------

git add Formula/airsnare.rb
git commit -m "Formula: update to ${TAG}"
git push origin master

# -----------------------------------------------------------------------
# 7. Update homebrew-airsnare tap repo
# -----------------------------------------------------------------------

echo "→ Updating tap repo at ${TAP_DIR}"
sed -i '' "s|url \"[^\"]*\"|url \"${TARBALL_URL}\"|"   "${TAP_DIR}/Formula/airsnare.rb"
sed -i '' "s|sha256 \"[^\"]*\"|sha256 \"${SHA256}\"|"  "${TAP_DIR}/Formula/airsnare.rb"

git -C "${TAP_DIR}" add Formula/airsnare.rb
git -C "${TAP_DIR}" commit -m "Update to ${TAG}"
git -C "${TAP_DIR}" push origin master

# -----------------------------------------------------------------------

echo ""
echo "✓ Release ${TAG} complete."
echo ""
echo "  Main repo  : ${REPO_URL}"
echo "  Tap repo   : $(git -C "${TAP_DIR}" remote get-url origin 2>/dev/null || echo "${TAP_DIR}")"
echo ""
echo "Install / upgrade with:"
echo "  brew tap rtulke/airsnare"
echo "  brew install rtulke/airsnare/airsnare"
echo ""
echo "Or to upgrade an existing install:"
echo "  brew update && brew upgrade airsnare"
