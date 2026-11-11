#!/bin/sh
# Build the release of the plugin in build/:
#  - build/OpenIdConnect/: files of the last commit (HEAD), without the
#    export-ignore paths of .gitattributes (.github...), plus vendor/;
#  - build/OpenIdConnect.zip, unless NO_ZIP=1.
# The directory must be named OpenIdConnect: the name is the plugin id, used in
# the callback URL registered at the provider (plugins/OpenIdConnect/auth.php).
#
# Requires git, composer and zip. With Docker only, from the repository root:
#   docker run --rm -v "$PWD":/app -w /app composer:2 sh build-release.sh
set -eu
cd "$(dirname "$0")"

if [ -n "$(git -c safe.directory="$PWD" status --porcelain --untracked-files=no)" ]; then
  echo "Warning: uncommitted changes are not included (the build uses HEAD)" >&2
fi

rm -rf build
mkdir build
git -c safe.directory="$PWD" archive --format=tar --prefix=OpenIdConnect/ HEAD | tar -x -C build
composer install --working-dir=build/OpenIdConnect --no-dev --no-interaction --no-progress --optimize-autoloader

if [ "${NO_ZIP:-}" != 1 ]; then
  (cd build && zip -qr OpenIdConnect.zip OpenIdConnect)
  echo "Built build/OpenIdConnect.zip"
fi
