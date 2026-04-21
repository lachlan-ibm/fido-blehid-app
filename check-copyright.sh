#!/bin/bash
#
# Copyright IBM 2025
#
# Script to manually run the copyright header check and update

# Parse command line arguments
DRY_RUN=false

for arg in "$@"; do
  case $arg in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    *)
      # Unknown option
      ;;
  esac
done

# Change to the project root directory
cd "$(dirname "$0")"

# Run the Gradle task to check and update copyright headers
if [ "$DRY_RUN" = true ]; then
  echo "Running in dry-run mode. No files will be modified."
  ./gradlew checkCopyrightHeaders -PdryRun=true
else
  ./gradlew checkCopyrightHeaders
fi

echo ""
echo "Copyright header check completed."
if [ "$DRY_RUN" = true ]; then
  echo "This was a dry run. To apply changes, run without the --dry-run flag."
else
  echo "You can review the changes and commit them if they look good."
fi

# Made with Bob
