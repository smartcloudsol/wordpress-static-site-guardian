# CloudFormation Template Validation

This document describes the comprehensive validation tools available for the WordPress Static Site Guardian CloudFormation template.

## Validation Scripts

### 1. Bash Validation Script (`validate-sam-template.sh`)

A comprehensive bash script that performs multiple validation checks on the SAM template.

#### Usage

```bash
# Basic validation
./tests/validate-sam-template.sh

# Strict mode (warnings treated as errors)
./tests/validate-sam-template.sh --strict

# Skip linting for faster validation
./tests/validate-sam-template.sh --skip-lint

# Verbose output
./tests/validate-sam-template.sh --verbose

# Validate specific template
./tests/validate-sam-template.sh --template my-template.yaml

# Show help
./tests/validate-sam-template.sh --help
```

#### Validation Checks

- **SAM CLI Prerequisites**: Checks if SAM CLI is installed and available
- **Template Syntax**: Validates YAML syntax and SAM template structure
- **SAM Linting**: Runs SAM linting rules for best practices
- **Parameter Validation**: Checks required parameters and validation patterns
- **Resource Validation**: Validates critical and custom resources
- **Lambda Function Validation**: Checks Lambda function configurations
- **IAM Permissions**: Validates required IAM permissions
- **CloudFront Configuration**: Checks CloudFront distribution settings
- **Output Validation**: Validates template outputs

### 2. Python Validation Script (`validate_template.py`)

An advanced Python script that provides detailed template analysis and validation.

#### Usage

```bash
# Basic validation
python3 tests/validate_template.py

# Verbose output with detailed checks
python3 tests/validate_template.py --verbose

# Validate specific template
python3 tests/validate_template.py --template my-template.yaml

# Show help
python3 tests/validate_template.py --help
```

#### Advanced Validation Features

- **CloudFormation-Aware YAML Parsing**: Handles intrinsic functions like `!Ref`, `!GetAtt`, etc.
- **Deep Resource Analysis**: Analyzes resource properties and dependencies
- **Security Best Practices**: Validates security configurations
- **Lambda Function Analysis**: Checks Lambda configurations and dependencies
- **IAM Policy Analysis**: Validates IAM permissions and policies
- **Custom Resource Validation**: Validates custom CloudFormation resources

## Validation Categories

### 1. Template Structure
- AWSTemplateFormatVersion presence
- SAM Transform validation
- Description and metadata validation

### 2. Parameters
- Required parameters presence
- Parameter types and constraints
- Validation patterns for critical parameters
- Default values and descriptions

### 3. Resources
- Critical resources presence (S3, CloudFront, Lambda functions)
- Custom resources validation
- Resource dependencies and references
- Resource property validation

### 4. Lambda Functions
- Code directory and handler validation
- Timeout and memory configurations
- Layer dependencies (cryptography layer)
- Environment variables validation

### 5. IAM Permissions
- CloudFront management permissions
- Lambda execution permissions
- KMS and SSM access permissions
- Least privilege validation

### 6. CloudFront Configuration
- Distribution configuration
- Cache behaviors validation
- NoCachePolicy integration
- Custom domain configuration

### 7. Security Best Practices
- S3 bucket security (public access block, encryption)
- Lambda function security
- IAM role security
- Sensitive data handling

### 8. Outputs
- Critical outputs presence
- Output descriptions and values
- Export names validation

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Template Validation
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup SAM CLI
        uses: aws-actions/setup-sam@v2
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install pyyaml
      - name: Run bash validation
        run: ./tests/validate-sam-template.sh --strict
      - name: Run Python validation
        run: python3 tests/validate_template.py --verbose
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "Running CloudFormation template validation..."

# Run bash validation
if ! ./tests/validate-sam-template.sh --strict; then
    echo "❌ Bash validation failed"
    exit 1
fi

# Run Python validation
if ! python3 tests/validate_template.py; then
    echo "❌ Python validation failed"
    exit 1
fi

echo "✅ All validations passed"
```

## Validation Results

Both scripts provide detailed output with:

- **Color-coded results**: Green for success, yellow for warnings, red for errors
- **Detailed summaries**: Total checks, passed checks, warnings, and errors
- **Actionable feedback**: Clear next steps based on validation results
- **Exit codes**: 0 for success, 1 for failure (CI/CD friendly)

## Best Practices

1. **Run validation before deployment**: Always validate templates before deploying
2. **Use strict mode in CI/CD**: Treat warnings as errors in automated pipelines
3. **Regular validation**: Run validation after any template changes
4. **Both scripts**: Use both bash and Python scripts for comprehensive coverage
5. **Version control**: Keep validation scripts in version control with templates

## Troubleshooting

### Common Issues

1. **SAM CLI not found**: Install SAM CLI from AWS documentation
2. **Python dependencies**: Install PyYAML with `pip install pyyaml`
3. **Permission errors**: Make scripts executable with `chmod +x`
4. **Template not found**: Ensure template.yaml exists in current directory

### Debug Mode

For debugging validation issues:

```bash
# Bash script with verbose output
./tests/validate-sam-template.sh --verbose

# Python script with verbose output
python3 tests/validate_template.py --verbose

# Manual SAM validation
sam validate --template template.yaml --lint
```

## Validation Checklist

Before deployment, ensure:

- [ ] Both validation scripts pass without errors
- [ ] All required parameters are defined with proper constraints
- [ ] All critical resources are present and properly configured
- [ ] Lambda functions have correct handlers and timeouts
- [ ] IAM permissions follow least privilege principle
- [ ] CloudFront configuration includes NoCachePolicy
- [ ] Security best practices are implemented
- [ ] All outputs are properly defined

## Support

For validation issues or questions:

1. Check the validation output for specific error messages
2. Review the template against the validation checklist
3. Ensure all prerequisites (SAM CLI, Python) are installed
4. Run validation in verbose mode for detailed information