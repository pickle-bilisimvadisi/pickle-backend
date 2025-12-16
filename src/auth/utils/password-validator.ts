export interface PasswordValidationResult {
  isValid: boolean;
  errors: string[];
  strength: 'weak' | 'medium' | 'strong';
}

export interface PasswordRequirement {
  regex: RegExp;
  message: string;
  met?: boolean;
}

export class PasswordValidator {
  private static readonly requirements: PasswordRequirement[] = [
    {
      regex: /.{8,}/,
      message: 'At least 8 characters long'
    },
    {
      regex: /[A-Z]/,
      message: 'At least one uppercase letter (A-Z)'
    },
    {
      regex: /[a-z]/,
      message: 'At least one lowercase letter (a-z)'
    },
    {
      regex: /\d/,
      message: 'At least one number (0-9)'
    }
  ];

  /**
   * Validates a password against all requirements
   */
  static validate(password: string): PasswordValidationResult {
    const errors: string[] = [];
    let metRequirements = 0;

    this.requirements.forEach(requirement => {
      if (!requirement.regex.test(password)) {
        errors.push(requirement.message);
      } else {
        metRequirements++;
      }
    });

    const isValid = errors.length === 0;
    let strength: 'weak' | 'medium' | 'strong' = 'weak';

    if (metRequirements >= 4) {
      strength = 'strong';
    } else if (metRequirements >= 3) {
      strength = 'medium';
    }

    return {
      isValid,
      errors,
      strength
    };
  }

  /**
   * Gets all requirements with their current status for a given password
   */
  static getRequirementsStatus(password: string): PasswordRequirement[] {
    return this.requirements.map(requirement => ({
      ...requirement,
      met: requirement.regex.test(password)
    }));
  }

  /**
   * Checks if password is strong enough (meets all requirements)
   */
  static isStrong(password: string): boolean {
    return this.validate(password).isValid;
  }

  /**
   * Gets password strength score (0-4)
   */
  static getStrengthScore(password: string): number {
    return this.requirements.filter(req => req.regex.test(password)).length;
  }

  /**
   * Generates a user-friendly strength message
   */
  static getStrengthMessage(password: string): string {
    const { strength, isValid } = this.validate(password);
    
    if (isValid) {
      return 'Strong password! ✅';
    }
    
    switch (strength) {
      case 'medium':
        return 'Good password, but could be stronger 💪';
      case 'weak':
        return 'Weak password. Please follow the requirements below ⚠️';
      default:
        return 'Please enter a password';
    }
  }
}

// Frontend React/Vue.js example usage:
/*
import { PasswordValidator } from './password-validator';

// In your component:
const handlePasswordChange = (password: string) => {
  const validation = PasswordValidator.validate(password);
  
  if (validation.isValid) {
    // Password is valid, enable submit button
    setPasswordValid(true);
    setPasswordErrors([]);
  } else {
    // Show validation errors
    setPasswordValid(false);
    setPasswordErrors(validation.errors);
  }
  
  // Show strength indicator
  setPasswordStrength(validation.strength);
};

// For real-time requirements display:
const requirements = PasswordValidator.getRequirementsStatus(password);
*/ 