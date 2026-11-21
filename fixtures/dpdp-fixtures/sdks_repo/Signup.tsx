import React from 'react';

export const SignupForm: React.FC = () => {
  return (
    <form className="p-4 space-y-4">
      <input type="email" placeholder="Email" required />
      <input type="password" placeholder="Password" required />
      
      {/* Dark Pattern: Pre-ticked consent checkbox */}
      <label>
        <input type="checkbox" defaultChecked name="marketing_consent" />
        I agree to receive promotional marketing emails and partner offers.
      </label>

      <button type="submit">Register</button>
    </form>
  );
};
