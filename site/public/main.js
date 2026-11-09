(function () {
  'use strict';

  // ── Waitlist capture ──────────────────────────────────────────────
  // Posts to our Cloudflare Pages Function (functions/api/subscribe.js),
  // which subscribes the email to Buttondown (no API key needed — it uses
  // Buttondown's public embed endpoint). The function only exists on the
  // deployed site, so the form is inert during local file:// preview.
  var WAITLIST_ENDPOINT = '/api/subscribe';

  function initWaitlist() {
    var form = document.getElementById('waitlist-form');
    if (!form) return;
    var input = document.getElementById('waitlist-email');
    var status = document.getElementById('waitlist-status');
    var btn = form.querySelector('button');

    function setStatus(msg, cls) {
      if (!status) return;
      status.textContent = msg;
      status.className = 'waitlist-note' + (cls ? ' ' + cls : '');
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var email = (input && input.value ? input.value : '').trim();
      if (!email || email.indexOf('@') === -1) {
        setStatus('Please enter a valid email.', 'err');
        return;
      }
      if (!WAITLIST_ENDPOINT) {
        setStatus('The waitlist isn’t open just yet — check back soon.', '');
        return;
      }
      btn.disabled = true;
      setStatus('Adding you…', '');
      fetch(WAITLIST_ENDPOINT, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
      })
        .then(function (r) {
          if (r.ok) {
            form.reset();
            form.classList.add('done');
            setStatus('You’re on the list. We’ll email you at launch.', 'ok');
          } else {
            setStatus('Something went wrong — try again in a moment.', 'err');
            btn.disabled = false;
          }
        })
        .catch(function () {
          setStatus('Network error — try again in a moment.', 'err');
          btn.disabled = false;
        });
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initWaitlist);
  else initWaitlist();
})();
