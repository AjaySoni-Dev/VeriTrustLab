document.addEventListener('DOMContentLoaded', async () => {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const forms = document.querySelectorAll('.auth-form');
  const message = document.getElementById('authMessage');
  const demoLoginButton = document.getElementById('demo-login-button');
  const params = new URLSearchParams(window.location.search);
  const redirectTarget = window.VeriTrustAuthFlow?.safeRedirect(params.get('redirect')) || 'dashboard.html';
  const demoCredentials = Object.freeze({
    email: 'example@gmail.com',
    password: 'example@gmail.com',
  });

  const showMessage = (text, tone = 'info') => {
    if (!message) return;
    message.textContent = text;
    message.dataset.tone = tone;
    message.classList.add('active');
  };

  const setSubmitting = (form, submitting) => {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    if (!button.dataset.defaultLabel) button.dataset.defaultLabel = button.textContent;
    button.disabled = submitting;
    button.textContent = submitting ? 'Please wait...' : button.dataset.defaultLabel;
    if (form.dataset.authMode === 'login' && demoLoginButton) {
      if (!demoLoginButton.dataset.defaultLabel) demoLoginButton.dataset.defaultLabel = demoLoginButton.textContent;
      demoLoginButton.disabled = submitting;
      demoLoginButton.textContent = submitting ? 'Signing in...' : demoLoginButton.dataset.defaultLabel;
    }
  };

  const activateForm = (targetId) => {
    tabBtns.forEach((item) => item.classList.toggle('active', item.getAttribute('data-target') === targetId));
    forms.forEach((form) => form.classList.toggle('active', form.id === targetId));
  };

  const authConfigured = Boolean(window.VeriTrustSupabase?.isConfigured());
  if (!authConfigured) showMessage('Account access is temporarily unavailable.', 'error');

  const pageAccess = window.VeriTrustPageAccess ? await window.VeriTrustPageAccess : null;
  if (pageAccess && !pageAccess.allowed) return;

  if (pageAccess?.callbackError) {
    showMessage(pageAccess.callbackError.message || 'The authentication link is invalid or has expired.', 'error');
  } else if (pageAccess?.sessionError) {
    showMessage('Your existing session could not be verified right now. It has not been cleared; refresh shortly or sign in again.', 'error');
  }

  if (pageAccess?.callback?.type === 'recovery') {
    document.querySelector('.auth-tabs')?.setAttribute('hidden', '');
    document.querySelector('.provider-note')?.setAttribute('hidden', '');
    forms.forEach((form) => form.classList.remove('active'));
    document.getElementById('recovery-form')?.classList.add('active');
    const subtitle = document.querySelector('.auth-header p');
    if (subtitle) subtitle.textContent = 'Choose a new password for your account';
    showMessage('Your recovery link is verified. Set your new password below.', 'success');
  }

  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      activateForm(targetId);
      if (message) message.classList.remove('active');
    });
  });

  if (!authConfigured) {
    if (demoLoginButton) demoLoginButton.disabled = true;
    forms.forEach((form) => {
      const submit = form.querySelector('button[type="submit"]');
      if (submit) submit.disabled = true;
    });
    return;
  }

  demoLoginButton?.addEventListener('click', () => {
    const loginForm = document.getElementById('login-form');
    const emailInput = document.getElementById('login-email');
    const passwordInput = document.getElementById('login-password');
    if (!loginForm || !emailInput || !passwordInput) return;

    activateForm('login-form');
    emailInput.value = demoCredentials.email;
    passwordInput.value = demoCredentials.password;
    emailInput.dispatchEvent(new Event('input', { bubbles: true }));
    passwordInput.dispatchEvent(new Event('input', { bubbles: true }));
    showMessage('Demo credentials filled. Signing you in now...', 'info');
    loginForm.requestSubmit();
  });

  forms.forEach((form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      setSubmitting(form, true);

      try {
        if (form.dataset.authMode === 'password-update') {
          const password = document.getElementById('recovery-password')?.value || '';
          const confirm = document.getElementById('recovery-confirm')?.value || '';
          if (password !== confirm) throw new Error('Passwords do not match.');
          await window.VeriTrustSupabase.updatePassword(password);
          showMessage('Password updated. Opening your requested VeriTrust page...', 'success');
          window.location.href = redirectTarget;
          return;
        }

        if (form.dataset.authMode === 'signup') {
          const password = document.getElementById('signup-password')?.value || '';
          const confirm = document.getElementById('signup-confirm')?.value || '';
          if (password !== confirm) {
            throw new Error('Passwords do not match.');
          }

          const data = await window.VeriTrustSupabase.signUp({
            fullName: document.getElementById('signup-name')?.value.trim() || '',
            email: document.getElementById('signup-email')?.value.trim() || '',
            password,
            workspaceName: document.getElementById('signup-workspace')?.value.trim() || '',
          });

          if (data?.authenticated) {
            showMessage('Account created. Opening your requested VeriTrust page...', 'success');
            window.location.href = redirectTarget;
          } else {
            showMessage('Account created. Check your email to confirm your account, then sign in.', 'success');
          }
          return;
        }

        await window.VeriTrustSupabase.signIn({
          email: document.getElementById('login-email')?.value.trim() || '',
          password: document.getElementById('login-password')?.value || '',
        });
        showMessage('Signed in. Opening your requested VeriTrust module...', 'success');
        window.location.href = redirectTarget;
      } catch (error) {
        showMessage(error.message || 'Authentication failed.', 'error');
      } finally {
        setSubmitting(form, false);
      }
    });
  });

  document.querySelector('[data-auth-action="reset"]')?.addEventListener('click', async (event) => {
    event.preventDefault();
    const email = document.getElementById('login-email')?.value.trim() || '';
    if (!email) {
      showMessage('Enter your email address first, then request a password reset.', 'info');
      return;
    }
    try {
      await window.VeriTrustSupabase.resetPassword(email);
      showMessage('Password reset email sent. Check your inbox for the recovery link.', 'success');
    } catch (error) {
      showMessage(error.message || 'Unable to send password reset email.', 'error');
    }
  });
});
