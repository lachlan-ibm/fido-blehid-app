<!--
 Copyright IBM 2025
-->
# Copyright Header Management

This project includes an automated system for checking and updating copyright headers in source files. The system ensures that all source files have the appropriate copyright headers with the correct year format.

## Features

- **Automatic Detection**: Identifies files missing copyright headers
- **Year Management**: Updates copyright years based on file modification dates
- **Format Enforcement**: Ensures copyright headers follow the standard format (at most two years)
- **Multiple File Types**: Supports various file types including Java, Gradle, shell scripts, XML, HTML, CSS, JavaScript, Python, and more
- **CI/CD Integration**: Integrated into the CI/CD pipeline to ensure all code has proper copyright headers

## Usage

### Manual Check and Update

To manually check and update copyright headers, run:

```bash
./check-copyright.sh
```

This will:
1. Check all source files for copyright headers
2. Add headers to files that are missing them
3. Update headers in files that have been modified in the current year
4. Print a report of the changes made

### Dry Run Mode

To see what changes would be made without actually making them, use the `--dry-run` flag:

```bash
./check-copyright.sh --dry-run
```

This will show you what changes would be made without actually modifying any files.

### Gradle Integration

The copyright check is integrated into the Gradle build process. It runs automatically before compilation:

```bash
./gradlew build
```

To run just the copyright check task:

```bash
./gradlew checkCopyrightHeaders
```

With dry run mode:

```bash
./gradlew checkCopyrightHeaders -PdryRun=true
```

## Copyright Header Format

The standard copyright header format is:

For Java, Gradle, JavaScript, C/C++, CSS files:
```java
/*
 * Copyright IBM YYYY
 */
```

For shell scripts, properties, Python, YAML files:
```bash
# Copyright IBM YYYY
```

For Markdown, HTML, XML files:
```html
<!--
 Copyright IBM YYYY
-->
```

Where `YYYY` is either a single year or two years separated by a comma (e.g., `2023, 2025`).

## Configuration

The copyright check system is configured in the `copyright-hook.gradle` file. You can modify:

- File patterns to check
- Directories to exclude
- Copyright header pattern
- Comment styles for different file types

## Troubleshooting

If the CI/CD build fails due to missing copyright headers:

1. Run `./check-copyright.sh --dry-run` locally to see what files are missing headers
2. Run `./check-copyright.sh` to add the headers
3. Commit and push the changes