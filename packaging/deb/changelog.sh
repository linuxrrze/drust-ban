#!/bin/sh
# Writes a debian/changelog for one binary package to stdout, generated from
# git (cargo-deb installs it as /usr/share/doc/<package>/changelog.Debian.gz):
#
#   packaging/deb/changelog.sh <package> <version>
#
# One entry for <version> (the full Debian version, e.g. 0.1.0-1), listing
# the commit subjects since the previous v* tag (all commits if there is
# none), dated like HEAD so that rebuilds of a commit are identical. Without
# git history (an export, a shallow clone) the entry names the commit only.
set -eu

pkg=${1:?usage: $0 <package> <version>}
version=${2:?usage: $0 <package> <version>}
maintainer="Marcel Ritter <marcel@linux-ng.de>"

cd "$(dirname "$0")/../.."

if commit=$(git rev-parse --short=12 HEAD 2>/dev/null); then
    date=$(git log -1 --format=%cD HEAD)
    # the previous release: the newest v* tag before HEAD
    if prev=$(git describe --tags --abbrev=0 --match 'v*' HEAD^ 2>/dev/null); then
        range="$prev..HEAD"
    else
        range=HEAD
    fi
    # changes: most recent first, wrapped to lintian's 80 columns
    changes=$(git log --no-merges --format='%s' "$range" | awk '{
        line = "  *"
        for (i = 1; i <= NF; i++) {
            if (length(line) + 1 + length($i) > 78 && line != "  *") {
                print line
                line = "   "
            }
            line = line " " $i
        }
        print line
    }')
    if [ "$(git rev-parse --is-shallow-repository)" = true ]; then
        changes="  * Built from commit $commit (no history available)."
    fi
else
    date=$(date -R ${SOURCE_DATE_EPOCH:+-d "@$SOURCE_DATE_EPOCH"})
    changes="  * Built from a source tree without git history."
fi

printf '%s (%s) unstable; urgency=medium\n\n%s\n\n -- %s  %s\n' \
    "$pkg" "$version" "$changes" "$maintainer" "$date"
