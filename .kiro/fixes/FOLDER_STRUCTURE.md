# WordPress Static Site Guardian - Folder Structure

This document describes the organized folder structure of the WordPress Static Site Guardian project.

## 📁 Project Structure

```
wordpress-static-site-guardian/
├── 📁 src/                          # Lambda function source code
│   ├── 📄 lambda_function.py        # Cookie signing Lambda function
│   ├── 📄 cloudfront_manager.py     # CloudFront resource manager Lambda
│   └── 📄 requirements.txt          # Python dependencies
├── 📁 scripts/                      # Deployment and utility scripts
│   ├── 📄 deploy-from-sar.sh        # Deploy from Serverless Application Repository
│   ├── 📄 deploy-infrastructure.sh  # Direct infrastructure deployment
│   ├── 📄 deploy-sar.sh             # Deploy to SAR (for maintainers)
│   └── 📄 generate-cloudfront-keypair.sh  # RSA key pair generation
├── 📁 tests/                        # Validation and testing scripts
│   ├── 📄 validate-sam-template.sh  # Comprehensive SAM template validation
│   ├── 📄 validate_template.py      # Advanced Python template validator
│   ├── 📄 test_end_to_end.py        # End-to-end functionality testing
│   ├── 📄 test_nocache_policy.py    # NoCachePolicy functionality validation
│   └── 📄 test_deployment_cleanup.py # Deployment and cleanup validation
├── 📁 .kiro/                        # Kiro IDE specification files
│   └── 📁 specs/
│       └── 📁 wordpress-static-site-guardian/
│           ├── 📄 requirements.md   # Project requirements specification
│           ├── 📄 design.md         # System design document
│           └── 📄 tasks.md          # Implementation task list
├── 📄 template.yaml                 # Main CloudFormation/SAM template
├── 📄 README.md                     # Main project documentation
├── 📄 LICENSE                       # MIT License
└── 📄 .gitignore                    # Git ignore rules
```

## 📂 Folder Descriptions

### `/src/` - Lambda Function Source Code
Contains the Python source code for AWS Lambda functions:

- **`lambda_function.py`**: Main cookie signing Lambda function that handles cookie issuance and expiration
- **`cloudfront_manager.py`**: Custom CloudFormation resource manager for CloudFront components
- **`requirements.txt`**: Python dependencies (boto3, cryptography)

### `/scripts/` - Deployment and Utility Scripts
Contains bash scripts for deployment and key management:

- **`deploy-from-sar.sh`**: Deploy the application from AWS Serverless Application Repository
- **`deploy-infrastructure.sh`**: Direct deployment using CloudFormation/SAM
- **`deploy-sar.sh`**: Deploy the application to SAR (for maintainers)
- **`generate-cloudfront-keypair.sh`**: Generate RSA key pairs and store in AWS KMS/SSM

### `/tests/` - Validation and Testing Scripts
Contains comprehensive validation and testing tools:

- **`validate-sam-template.sh`**: Bash script for comprehensive SAM template validation
- **`validate_template.py`**: Advanced Python script for detailed template analysis
- **`test_end_to_end.py`**: End-to-end functionality testing suite
- **`test_nocache_policy.py`**: Specific validation for NoCachePolicy functionality
- **`test_deployment_cleanup.py`**: Deployment and cleanup procedures validation

### `/.kiro/` - Kiro IDE Specification Files
Contains project specification and design documents:

- **`requirements.md`**: Detailed project requirements with acceptance criteria
- **`design.md`**: System architecture and design documentation
- **`tasks.md`**: Implementation task list with completion status

## 🚀 Usage Examples

### Deployment
```bash
# Generate RSA key pairs
./scripts/generate-cloudfront-keypair.sh --name my-keys --region us-east-1

# Deploy from SAR
./scripts/deploy-from-sar.sh \
  --stack-name my-wordpress-protection \
  --domain example.com \
  --api-domain api.example.com \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/... \
  --kms-key-id 12345678-1234-1234-1234-123456789012 \
  --public-key-content "MIIBIjANBgkqhkiG9w0BAQEF..."
```

### Validation
```bash
# Quick validation
./tests/validate-sam-template.sh

# Comprehensive validation
./tests/validate-sam-template.sh --strict --verbose
python3 tests/validate_template.py --verbose

# End-to-end testing
python3 tests/test_end_to_end.py --verbose
```

### Testing
```bash
# Test NoCachePolicy functionality
python3 tests/test_nocache_policy.py

# Test deployment procedures
python3 tests/test_deployment_cleanup.py

# Run all tests
for test in tests/test_*.py; do
    echo "Running $test..."
    python3 "$test"
done
```

## 🔧 Development Workflow

### 1. Template Changes
When modifying `template.yaml`:
```bash
# Validate changes
./tests/validate-sam-template.sh --strict
python3 tests/validate_template.py --verbose

# Test functionality
python3 tests/test_end_to_end.py
```

### 2. Lambda Function Changes
When modifying files in `/src/`:
```bash
# Validate syntax
python3 -m py_compile src/lambda_function.py
python3 -m py_compile src/cloudfront_manager.py

# Run comprehensive tests
python3 tests/test_end_to_end.py --verbose
```

### 3. Script Changes
When modifying files in `/scripts/`:
```bash
# Test script functionality
bash -n scripts/script-name.sh  # Syntax check
./scripts/script-name.sh --help  # Test help output

# Validate deployment procedures
python3 tests/test_deployment_cleanup.py
```

## 📋 File Dependencies

### Scripts Dependencies
- `deploy-from-sar.sh` → references `scripts/generate-cloudfront-keypair.sh`
- `deploy-infrastructure.sh` → uses `template.yaml`
- `deploy-sar.sh` → uses `template.yaml`

### Test Dependencies
- `test_end_to_end.py` → references `tests/validate-sam-template.sh` and `tests/validate_template.py`
- `test_deployment_cleanup.py` → references validation scripts in `tests/`
- All test scripts → use `template.yaml` and `src/` files

### Template Dependencies
- `template.yaml` → uses `src/lambda_function.py` and `src/cloudfront_manager.py`
- Lambda functions → use `src/requirements.txt`

## 🔄 Migration Notes

This folder structure was organized from a flat structure to improve maintainability:

### Previous Structure (Flat)
```
├── validate-sam-template.sh
├── validate_template.py
├── test_*.py
├── deploy-*.sh
├── generate-*.sh
└── create-*.sh
```

### Current Structure (Organized)
```
├── scripts/          # All bash scripts
├── tests/           # All validation and test scripts
└── src/             # Lambda source code
```

### Breaking Changes
- All script references now require folder prefixes
- Test scripts moved to `tests/` folder
- Deployment scripts moved to `scripts/` folder
- Documentation updated to reflect new paths

## 🎯 Best Practices

### Adding New Scripts
- **Deployment scripts** → Add to `/scripts/`
- **Validation scripts** → Add to `/tests/`
- **Test scripts** → Add to `/tests/`
- **Lambda code** → Add to `/src/`

### Naming Conventions
- **Deployment scripts**: `deploy-*.sh`
- **Validation scripts**: `validate*.sh` or `validate*.py`
- **Test scripts**: `test_*.py`
- **Utility scripts**: `generate-*.sh`, `create-*.sh`

### Documentation Updates
When adding new files, update:
1. This `FOLDER_STRUCTURE.md` file
2. Main `README.md` with usage examples
3. `VALIDATION.md` if adding validation tools
4. Any scripts that reference the new files