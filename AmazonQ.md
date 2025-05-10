# AWS Vault Lite - Development Notes

This document contains development notes and information about the AWS Vault Lite project.

## Project Overview

AWS Vault Lite is a graphical tool for managing secrets using the Single Secret Design (SSD) pattern in AWS Secrets Manager. The application provides a user-friendly interface for creating, viewing, editing, and deleting secrets stored in a single JSON structure.

## Implementation Details

### Technologies Used
- Python 3.13
- CustomTkinter for the GUI
- boto3 for AWS API interactions

### Key Components
1. **Main Application (AWSVaultLite class)**: Handles the overall application flow, AWS client initialization, and UI setup.
2. **PasswordEntry Widget**: Custom widget for password fields with show/hide functionality.
3. **AttributeRow Widget**: Custom widget for displaying and editing key-value pairs with password toggle functionality.

### AWS Integration
- Uses environment variables for AWS authentication
- Connects to AWS Secrets Manager in the us-east-1 region by default
- Implements CRUD operations for the `/aws-vault-lite/vault` secret

## Development Decisions

### GUI Framework Selection
CustomTkinter was chosen for its:
- Modern appearance compared to standard Tkinter
- Ease of use and minimal dependencies
- Cross-platform compatibility
- Built-in theming support

### Secret Management Approach
- All secrets are stored in a single JSON structure following the SSD pattern
- Password fields are automatically detected based on key names containing "password", "secret", "token", or "key"
- The application supports flexible attribute structures for each secret

## Future Enhancements

Potential improvements for future versions:
1. Support for AWS profiles instead of just environment variables
2. Custom region selection in the UI
3. Search functionality for secrets
4. Export/import capabilities
5. Dark/light theme toggle
6. Keyboard shortcuts for common operations
7. Automatic secret rotation capabilities
8. Integration with AWS KMS for additional encryption

## Development Environment Setup

See the README.md file for detailed setup instructions for different operating systems.

## Testing

Manual testing should cover:
1. Secret creation, viewing, editing, and deletion
2. Password field show/hide functionality
3. Error handling for AWS API failures
4. UI responsiveness with many secrets
