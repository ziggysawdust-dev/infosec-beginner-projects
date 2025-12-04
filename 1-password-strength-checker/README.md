# Password Strength Checker

## Overview
A Python tool that evaluates password strength based on security best practices.

## Learning Outcomes
- String manipulation and validation
- Regular expressions (regex)
- Security evaluation criteria
- User input handling

## Features
- Length validation (minimum 8 characters)
- Character variety checks (uppercase, lowercase, digits, special chars)
- Scoring system (0-6 scale)
- Detailed feedback for improvement

## Usage
```bash
# Interactive mode
python password_checker.py

# Command line argument
python password_checker.py "YourPassword123!"
```

## Strength Levels
- **Weak**: Score 0-1 - Easy to crack, avoid using
- **Medium**: Score 2-3 - Better, but could be improved
- **Strong**: Score 4+ - Good security level
- **Very Strong**: Score 5-6 - Excellent security

## Security Tips Demonstrated
1. Minimum length requirements
2. Character diversity
3. Avoiding common patterns
4. User feedback for improvement

## Next Steps
- Add dictionary checking to prevent common passwords
- Integrate with real password managers
- Create a GUI version using tkinter
